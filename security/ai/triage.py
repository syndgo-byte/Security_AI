"""AI 판정 — 기존 진단 결과를 여러 모델이 검토해 오탐 여부를 다수결로 정하고, 자동 수정이 없는 항목에는 수정안을 만든다.

판정은 표시만 한다 (자동으로 무시 처리하지 않음). 수정안도 승인해야 적용된다.
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import store
from ..findings import Edit, read_lines
from . import providers
from .common import majority, numbered, redact, require_code_consent

CONTEXT = 12
CODE_CATEGORIES = ("sast", "secrets", "config", "ai")

SYSTEM = """당신은 보안 진단 결과를 검토하는 감사자입니다. 정적 분석기가 낸 항목 하나와 주변 코드를 보고 판단합니다.
- true_positive: 실제로 악용 가능하거나 조치가 필요한 문제
- false_positive: 입력이 신뢰 가능한 상수뿐이거나, 이미 다른 곳에서 막혀 있거나, 테스트/예제 코드인 경우
- uncertain: 주어진 코드만으로는 판단 불가
true_positive 이고 표시된 줄(>> 표시) 한 줄을 바꿔서 고칠 수 있으면 new 에 대체 코드를 주세요(여러 줄 가능, 줄바꿈 \\n).
반드시 다음 JSON 객체 하나로만 답합니다 (한국어):
{"verdict":"true_positive|false_positive|uncertain","reason":"한두 문장 근거","new":"대체 코드 또는 빈 문자열"}"""


def _prompt(f: dict, lines: list[str]) -> str:
    ln = f["line"]
    lo, hi = max(1, ln - CONTEXT), min(len(lines), ln + CONTEXT)
    ctx = numbered(lines[lo - 1:hi], lo).splitlines()
    ctx = [(">>" + l) if l.startswith(f"{ln}|") else ("  " + l) for l in ctx]
    return (f"규칙: {f['rule']} ({f['severity']})\n제목: {f['title']}\n설명: {f['detail']}\n"
            f"파일: {f['file']}:{ln}\n\n{redact(chr(10).join(ctx))}")


def judge(f: dict, lines: list[str], answers: dict[str, dict]) -> dict:
    ok = {m: a for m, a in answers.items() if "error" not in a}
    votes = {m: str(a.get("verdict", "uncertain")) for m, a in ok.items()}
    decided = [v for v in votes.values() if v in ("true_positive", "false_positive")]
    verdict = majority(decided) or "uncertain"
    note = "\n".join(f"[{m}] {votes[m]} — {ok[m].get('reason', '')}" for m in ok)
    fix = None
    old = lines[f["line"] - 1]
    if verdict == "true_positive" and not (f["fix"] and f["fix"]["automatic"]):
        for m, a in ok.items():
            new = str(a.get("new") or "").replace("\\n", "\n")
            if votes[m] == "true_positive" and new.strip() and new.strip() != old.strip():
                indent = old[:len(old) - len(old.lstrip())]
                new = "\n".join(l if l.startswith(indent) else indent + l.lstrip() for l in new.splitlines())
                fix = {"description": f"AI 제안 ({m})", "edits": [Edit(f["file"], f["line"], old, new).__dict__]}
                break
    return {"verdict": verdict, "note": note, "models": ",".join(ok), "fix": fix}


def run(con, targets: dict[str, Path], service: str | None = None, allow_code: bool = False,
        limit: int = 30, redo: bool = False) -> dict:
    require_code_consent(allow_code)
    todo = [f for f in store.list_findings(con, service=service, status="open")
            if f["category"] in CODE_CATEGORIES and f["line"] > 0 and f["service"] in targets
            and (redo or not f.get("ai_verdict"))][:limit]
    counts = {"true_positive": 0, "false_positive": 0, "uncertain": 0, "patched": 0}
    errors = []
    for f in todo:
        path = targets[f["service"]] / f["file"]
        if not path.exists():
            continue
        lines = read_lines(path)
        if f["line"] > len(lines):
            continue
        answers = providers.ask_all(SYSTEM, _prompt(f, lines))
        errors += [f"{f['id']}: {m} {a['error']}" for m, a in answers.items() if "error" in a]
        if all("error" in a for a in answers.values()):
            continue
        r = judge(f, lines, answers)
        con.execute("update findings set ai_verdict=?, ai_note=?, ai_models=?, ai_fix=? where id=?",
                    (r["verdict"], r["note"], r["models"], json.dumps(r["fix"], ensure_ascii=False) if r["fix"] else None,
                     f["id"]))
        con.commit()
        counts[r["verdict"]] += 1
        counts["patched"] += bool(r["fix"])
    return {"checked": sum(counts[k] for k in ("true_positive", "false_positive", "uncertain")), **counts,
            "errors": errors}
