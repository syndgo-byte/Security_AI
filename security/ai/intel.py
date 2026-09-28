"""최신 위협 수집 — CISA KEV(실제 악용 중인 취약점)와 NVD 최근 공개 CVE 를 모아, 서비스 의존성과 맞는 것만 AI 가 추린다.

외부로 나가는 것은 공개 CVE 설명과 서비스의 패키지 이름 · 버전뿐이다 (코드는 보내지 않음).
AI 키가 없으면 CPE 제품명이 정확히 일치한 것만 '미확인'으로 남긴다.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..findings import Finding, Fix
from ..scanners import deps as deps_scanner
from . import providers
from .common import norm_severity

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_CANDIDATES = 40

SYSTEM = """당신은 취약점 정보 분석가입니다. 서비스가 쓰는 패키지 목록과 최근 공개된 CVE 후보를 보고,
그 서비스에 실제로 해당하는 CVE 만 고릅니다 (이름만 비슷한 다른 제품, 해당 버전이 영향 범위 밖인 것은 제외).
반드시 다음 JSON 객체 하나로만 답합니다 (한국어):
{"relevant":[{"cve":"CVE-...","package":"패키지명","reason":"해당한다고 본 근거","action":"권장 조치(업그레이드 버전 등)"}]}"""


def _get_json(url: str, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "security-module", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name.lower())


def fetch_kev() -> list[dict]:
    return [{"id": v["cveID"], "source": "KEV", "severity": "critical",
             "products": {_norm(v.get("product", "")), _norm(v.get("vendorProject", ""))},
             "text": f"{v.get('vendorProject')} {v.get('product')}: {v.get('vulnerabilityName')}. "
                     f"{v.get('shortDescription', '')} 조치: {v.get('requiredAction', '')}"}
            for v in _get_json(KEV_URL).get("vulnerabilities", [])]


def fetch_nvd(days: int) -> list[dict]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=min(days, 120))
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    out, index = [], 0
    while True:
        q = urllib.parse.urlencode({"pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                                    "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                                    "resultsPerPage": 2000, "startIndex": index})
        page = _get_json(f"{NVD_URL}?{q}", headers)
        for item in page.get("vulnerabilities", []):
            cve = item["cve"]
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            products = set()
            for conf in cve.get("configurations", []):
                for node in conf.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        parts = m.get("criteria", "").split(":")
                        if len(parts) > 4:
                            products.add(_norm(parts[4]))
            metrics = cve.get("metrics", {})
            sev = next((m[0]["cvssData"].get("baseSeverity") for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30")
                        if (m := metrics.get(k))), "medium")
            out.append({"id": cve["id"], "source": "NVD", "severity": norm_severity(sev), "products": products,
                        "text": desc})
        index += page.get("resultsPerPage", 0)
        if not page.get("resultsPerPage") or index >= page.get("totalResults", 0):
            return out


def match(dep_list: list, feed: list[dict]) -> list[tuple[dict, object, bool]]:
    """(취약점, 의존성, CPE 정확 일치 여부). 설명 본문 일치는 이름 5자 이상만."""
    out, seen = [], set()
    for v in feed:
        low = v["text"].lower()
        for d in dep_list:
            n = _norm(d.name)
            exact = n in v["products"]
            if exact or (len(n) >= 5 and re.search(rf"\b{re.escape(d.name.lower())}\b", low)):
                if (v["id"], d.name) not in seen:
                    seen.add((v["id"], d.name))
                    out.append((v, d, exact))
    out.sort(key=lambda x: (not x[2], x[0]["source"] != "KEV"))
    return out[:MAX_CANDIDATES]


def _prompt(service: str, dep_list: list, cands: list) -> str:
    pkgs = sorted({f"{d.name} {d.version or '(버전 미고정)'} [{d.ecosystem}]" for d in dep_list})
    cves = "\n".join(f"- {v['id']} ({v['source']}, {v['severity']}) 패키지후보={d.name}: {v['text'][:600]}"
                     for v, d, _ in cands)
    return f"서비스: {service}\n사용 패키지:\n" + "\n".join(pkgs) + f"\n\nCVE 후보:\n{cves}"


def _finding(service, v, d, detail, action) -> Finding:
    rule = "INTEL-KEV" if v["source"] == "KEV" else "INTEL-CVE"
    title = f"{v['id']} — {d.name}" + (" (실제 악용 중)" if v["source"] == "KEV" else " (최근 공개)")
    return Finding(service, "intel", rule, v["severity"], title, d.file, d.line, detail,
                   f"{v['id']} · {d.raw.strip()}"[:200], Fix(f"수동 조치: {action}" if action else f"수동 조치: {d.name} 업그레이드"))


def scan(targets: dict[str, Path], service: str | None = None, days: int = 14) -> tuple[dict[str, list[Finding]], list[str]]:
    errors: list[str] = []
    feed: list[dict] = []
    for name, fn in (("KEV", fetch_kev), ("NVD", lambda: fetch_nvd(days))):
        try:
            feed += fn()
        except (OSError, ValueError, KeyError) as e:
            errors.append(f"{name} 수집 실패: {e}")
    if not feed:
        return {}, errors   # 수집이 전부 실패했으면 이전 결과를 지우지 않는다
    use_ai = bool(providers.available())
    result: dict[str, list[Finding]] = {}
    for svc, root in targets.items():
        if service and svc != service:
            continue
        dep_list = [d for d in deps_scanner.collect(root) if d.line]
        cands = match(dep_list, feed)
        found: list[Finding] = []
        if cands and use_ai:
            answers = providers.ask_all(SYSTEM, _prompt(svc, dep_list, cands))
            ok = {m: a for m, a in answers.items() if "error" not in a}
            errors += [f"{svc}: {m} {a['error']}" for m, a in answers.items() if "error" in a]
            if not ok:
                continue
            need = (len(ok) + 1) // 2 or 1
            for v, d, _ in cands:
                picks = [(m, r) for m, a in ok.items() for r in a.get("relevant") or []
                         if str(r.get("cve", "")).upper() == v["id"] and _norm(str(r.get("package", d.name))) == _norm(d.name)]
                if len({m for m, _ in picks}) >= need:
                    reasons = "\n".join(f"[{m}] {r.get('reason', '')}" for m, r in picks)
                    found.append(_finding(svc, v, d, f"{v['text'][:800]}\n\n{reasons}\n\n모델 일치 {len(picks)}/{len(ok)}",
                                          str(picks[0][1].get("action") or "")))
        elif cands:
            for v, d, exact in cands:
                if exact:
                    sev = v["severity"] if v["source"] == "KEV" else max(v["severity"], "medium", key=("critical", "high", "medium", "low").index)
                    v = {**v, "severity": sev}
                    found.append(_finding(svc, v, d, f"{v['text'][:800]}\n\n제품명 일치만 확인 (AI 미확인, 버전 영향 범위 직접 확인)", ""))
        result[svc] = found
    return result, errors
