"""의존성 CVE — requirements · pyproject · package.json 을 OSV(api.osv.dev)에 조회.

온라인 조회 시 패키지 이름과 버전만 외부(OSV)로 전송된다. offline=True 면 조회하지 않고 미고정 버전만 점검.
"""
from __future__ import annotations

import json
import re
import tomllib
import urllib.request
from pathlib import Path

from ..findings import Edit, Finding, Fix, read_lines
from ..walk import iter_files

OSV = "https://api.osv.dev/v1"
REQ_RX = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([0-9][^\s;#,]*)?")


class Dep:
    def __init__(self, name, version, ecosystem, file, line, raw, pinned, op=None):
        self.name, self.version, self.ecosystem = name, version, ecosystem
        self.file, self.line, self.raw, self.pinned = file, line, raw, pinned
        self.op = "==" if pinned else op

    @property
    def floor(self) -> bool:
        """>= 하한만 있는 PyPI 의존성 — 하한 버전을 대신 조회한다 (설치될 수 있는 가장 낮은 버전)."""
        return self.op == ">=" and bool(self.version) and self.ecosystem == "PyPI"


def _requirements(path: Path, rel: str) -> list[Dep]:
    out = []
    for i, raw in enumerate(read_lines(path), 1):
        s = raw.split("#", 1)[0].strip()
        if not s or s.startswith(("-", "git+", "http")):
            continue
        m = REQ_RX.match(s)
        if m:
            out.append(Dep(m.group(1), m.group(4), "PyPI", rel, i, raw, m.group(3) == "==", m.group(3)))
    return out


def _pyproject(path: Path, rel: str) -> list[Dep]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []
    lines = read_lines(path)
    out = []
    for spec in data.get("project", {}).get("dependencies", []) or []:
        m = REQ_RX.match(spec)
        if not m:
            continue
        line = next((i for i, l in enumerate(lines, 1) if f'"{spec}"' in l or f"'{spec}'" in l), 0)
        out.append(Dep(m.group(1), m.group(4), "PyPI", rel, line, lines[line - 1] if line else spec, m.group(3) == "==",
                       m.group(3)))
    return out


def _package_json(path: Path, rel: str) -> list[Dep]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    lines = read_lines(path)
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            m = re.match(r"^[\^~]?(\d+\.\d+\.\d+[^\s]*)$", str(spec))
            line = next((i for i, l in enumerate(lines, 1) if f'"{name}"' in l), 0)
            out.append(Dep(name, m.group(1) if m else None, "npm", rel, line, lines[line - 1] if line else "",
                           bool(m) and not str(spec).startswith(("^", "~"))))
    return out


def collect(root: Path) -> list[Dep]:
    deps = []
    for path, rel in iter_files(root, ("requirements.txt", "pyproject.toml", "package.json", ".txt")):
        if path.name.startswith("requirements") and path.suffix == ".txt":
            deps += _requirements(path, rel)
        elif path.name == "pyproject.toml":
            deps += _pyproject(path, rel)
        elif path.name == "package.json":
            deps += _package_json(path, rel)
    return deps


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.load(r)


def _severity(vuln: dict) -> str:
    sev = (vuln.get("database_specific") or {}).get("severity", "").lower()
    if sev in ("critical", "high", "medium", "low"):
        return sev
    if sev == "moderate":
        return "medium"
    for s in vuln.get("severity") or []:
        m = re.search(r"CVSS:3\.\d/AV:N", s.get("score", ""))
        if m:
            return "high"
    return "medium"


def _fixed_version(vuln: dict, name: str) -> str | None:
    fixed = []
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges") or []:
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return max(fixed, key=_vkey) if fixed else None


def _vkey(v: str):
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.\-+]", v)[:4])


def scan(service: str, root: Path, offline: bool = False) -> list[Finding]:
    deps = collect(root)
    out: list[Finding] = []
    pinned = [d for d in deps if d.version and (d.pinned or d.floor)]
    unpinned: dict[str, list[Dep]] = {}
    for d in deps:
        if not d.pinned and d.ecosystem == "PyPI" and d.file.endswith(".txt"):
            unpinned.setdefault(d.file, []).append(d)
    for file, ds in unpinned.items():   # 파일당 한 건으로 묶는다
        names = ", ".join(d.name for d in ds)
        out.append(Finding(service, "deps", "DEPS-UNPINNED", "low", f"버전 미고정 {len(ds)}개", file, ds[0].line,
                           "배포마다 다른 버전이 설치될 수 있어 취약 버전 여부를 확정할 수 없습니다. "
                           "lock 파일(pip freeze > requirements.lock 등)을 두거나 == 로 고정하세요. >= 하한은 CVE 를 따로 조회합니다.",
                           names[:200]))
    if offline or not pinned:
        return out
    try:
        res = _post(f"{OSV}/querybatch", {"queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in pinned]})
    except OSError as e:
        out.append(Finding(service, "deps", "DEPS-OSV-UNREACHABLE", "low", "OSV 조회 실패", "", 0, str(e)))
        return out
    cache: dict[str, dict] = {}
    for d, r in zip(pinned, res.get("results", [])):
        vulns = r.get("vulns") or []
        if not vulns:
            continue
        details = []
        for v in vulns:
            if v["id"] not in cache:
                try:
                    cache[v["id"]] = _get(f"{OSV}/vulns/{v['id']}")
                except OSError:
                    cache[v["id"]] = {"id": v["id"]}
            details.append(cache[v["id"]])
        order = ("critical", "high", "medium", "low")
        sev = min((_severity(v) for v in details), key=order.index)
        fixes = [f for f in (_fixed_version(v, d.name) for v in details) if f]
        target = max(fixes, key=_vkey) if fixes else None
        ids = ", ".join(sorted({(v.get("aliases") or [v["id"]])[0] for v in details})[:6])
        summary = next((v.get("summary") for v in details if v.get("summary")), "")
        fix = None
        if d.floor:   # 실제 설치본은 더 새것일 수 있어 심각도는 medium 까지, 하한을 올리는 수정안
            sev = "medium" if order.index(sev) < order.index("medium") else sev
            fix = Fix(f"{d.name} 하한 {d.version} → {target}",
                      [Edit(d.file, d.line, d.raw, d.raw.replace(f">={d.version}", f">={target}", 1))]) \
                if target and d.line and f">={d.version}" in d.raw else None
            out.append(Finding(service, "deps", "DEPS-CVE-FLOOR", sev,
                               f"{d.name} 허용 하한 {d.version} 에 알려진 취약점 {len(details)}건", d.file, d.line,
                               f"{ids}. {summary} (하한 이상 아무 버전이나 설치될 수 있어, 낮은 버전이 깔리면 취약)".strip(),
                               d.raw.strip(), fix or Fix(f"수동 조치: {d.name} 하한 올리기" + (f" (≥ {target})" if target else ""))))
            continue
        if target and d.line:
            if d.ecosystem == "PyPI" and f"=={d.version}" in d.raw:
                fix = Fix(f"{d.name} {d.version} → {target}",
                          [Edit(d.file, d.line, d.raw, d.raw.replace(f"=={d.version}", f"=={target}", 1))])
            elif d.ecosystem == "npm" and f'"{d.version}"' in d.raw:
                fix = Fix(f"{d.name} {d.version} → {target} (npm install 필요)",
                          [Edit(d.file, d.line, d.raw, d.raw.replace(f'"{d.version}"', f'"{target}"', 1))])
        out.append(Finding(service, "deps", "DEPS-CVE", sev, f"{d.name} {d.version} 알려진 취약점 {len(details)}건",
                           d.file, d.line, f"{ids}. {summary}".strip(), d.raw.strip(),
                           fix or Fix(f"수동 조치: {d.name} 업그레이드" + (f" (≥ {target})" if target else ""))))
    return out
