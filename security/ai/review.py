"""AI 코드 검토 — 규칙으로 못 잡는 취약점(인가 누락, IDOR, 경로 조작, SSRF, 로직 결함 등)을 여러 모델이 찾는다.

모델이 준 줄 번호 · 기존 줄이 실제 파일과 맞을 때만 결과로 인정하고, 수정안도 그 줄이 그대로일 때만 패치로 만든다.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Edit, Finding, Fix, read_lines
from ..walk import iter_files
from . import providers
from .common import consensus_severity, majority, numbered, redact, require_code_consent

SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx")
MAX_CHARS = 14000
HOT = re.compile(r"route|router|request|@app\.|@router\.|execute|query|sql|password|token|auth|login|session|upload|"
                 r"open\(|subprocess|redirect|fetch\(|axios|innerHTML|jwt|permission|admin|cookie|consent", re.I)

SYSTEM = """당신은 보안 코드 감사자입니다. 주어진 파일에서 실제로 악용 가능한 취약점만 찾습니다.
대상: 인가/인증 누락, IDOR, SQL·명령·경로 주입, SSRF, XSS, 역직렬화, 안전하지 않은 암호 사용, 비밀값 노출,
개인정보(주민번호·연락처 등) 평문 저장·로그 출력, 레이스 컨디션, 비즈니스 로직 결함.
스타일 지적이나 추측성 항목은 넣지 마세요. 확신이 없으면 빼세요.
반드시 다음 JSON 객체 하나로만 답합니다 (설명 문장 금지, 한국어로 작성):
{"findings":[{"line":정수,"old":"그 줄의 원문 그대로","severity":"critical|high|medium|low","cwe":"CWE-번호",
"title":"짧은 제목","detail":"왜 위험한지와 조치","new":"그 한 줄을 대체할 코드(여러 줄 가능, 줄바꿈은 \\n). 한 줄 교체로 못 고치면 빈 문자열"}]}"""


def pick_files(root: Path, max_files: int) -> list[tuple[Path, str]]:
    scored = []
    for path, rel in iter_files(root, SUFFIXES):
        if "/tests/" in f"/{rel}" or path.name.startswith(("test_", "tests.")) or path.name.endswith((".min.js", ".d.ts")):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        score = len(HOT.findall(text))
        if score:
            scored.append((score, path, rel))
    scored.sort(key=lambda x: -x[0])
    return [(p, r) for _, p, r in scored[:max_files]]


def _prompt(rel: str, lines: list[str]) -> str:
    body = numbered(lines)
    if len(body) > MAX_CHARS:
        body = body[:MAX_CHARS] + "\n… (이하 생략)"
    return f"파일: {rel}\n각 줄 앞의 숫자는 줄 번호입니다.\n\n{redact(body)}"


def merge(service: str, rel: str, lines: list[str], answers: dict[str, dict]) -> list[Finding]:
    """모델별 답을 줄 단위로 합친다."""
    ok = {m: a for m, a in answers.items() if "error" not in a}
    by_line: dict[int, list[tuple[str, dict]]] = {}
    for model, a in ok.items():
        for item in a.get("findings") or []:
            try:
                ln = int(item.get("line"))
            except (TypeError, ValueError):
                continue
            if not 1 <= ln <= len(lines) or not lines[ln - 1].strip():
                continue
            old = str(item.get("old") or "")
            if old and old.strip() != lines[ln - 1].strip():
                continue   # 다른 줄을 짚었거나 지어낸 줄
            by_line.setdefault(ln, [])
            if model not in {m for m, _ in by_line[ln]}:
                by_line[ln].append((model, item))

    out = []
    for ln, hits in sorted(by_line.items()):
        models = [m for m, _ in hits]
        items = [i for _, i in hits]
        cwe = majority([str(i.get("cwe") or "").upper() for i in items if i.get("cwe")]) or \
            str(items[0].get("cwe") or "").upper()
        cwe = cwe if re.fullmatch(r"CWE-\d+", cwe) else ""
        sev = consensus_severity([i.get("severity") for i in items], len(models), len(ok))
        edit = None
        for i in items:
            new = str(i.get("new") or "").replace("\\n", "\n")
            if new.strip() and new.strip() != lines[ln - 1].strip():
                indent = lines[ln - 1][:len(lines[ln - 1]) - len(lines[ln - 1].lstrip())]
                new = "\n".join(l if l.startswith(indent) else indent + l.lstrip() for l in new.splitlines())
                edit = Edit(rel, ln, lines[ln - 1], new)
                break
        detail = "\n".join(f"[{m}] {i.get('detail', '')}".strip() for m, i in hits)
        detail += f"\n\n모델 일치 {len(models)}/{len(ok)} · AI 검토 결과는 반드시 사람이 확인하세요."
        out.append(Finding(
            service, "ai", f"AI-REVIEW-{cwe}" if cwe else "AI-REVIEW", sev,
            str(items[0].get("title") or "AI 검토 지적")[:120], rel, ln, detail, lines[ln - 1].strip()[:200],
            Fix(f"AI 제안 ({', '.join(models)})", [edit]) if edit else Fix("수동 조치: 내용 확인 후 수정")))
    return out


def scan(service: str, root: Path, allow_code: bool = False, max_files: int = 15) -> tuple[list[Finding], list[str]]:
    """(결과, 오류 메시지) — 오류는 모델별 실패 내역."""
    require_code_consent(allow_code)
    out, errors = [], []
    for path, rel in pick_files(root, max_files):
        lines = read_lines(path)
        answers = providers.ask_all(SYSTEM, _prompt(rel, lines))
        errors += [f"{rel}: {m} {a['error']}" for m, a in answers.items() if "error" in a]
        out += merge(service, rel, lines, answers)
    return out, errors
