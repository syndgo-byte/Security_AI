"""조치 정책 — 진단 항목마다 누가 처리할지 정한다.

escalate  critical → 무조건 사람에게 넘김 (허브 이벤트로 보고)
          high 인데 자동 수정이 없는 것도 넘김 (SQL 인젝션 · 키 노출 등 사람이 봐야 하는 것)
auto      규칙 기반 자동 수정이 있고 동작을 바꾸지 않는 것 → 모듈이 바로 조치 (서비스 저장소 새 브랜치에 커밋)
approve   수정안은 있지만 동작이 바뀔 수 있는 것 (AI 수정안 · 의존성 업그레이드 · 비밀값 이동 · CORS) → 승인 후 적용
manual    수정안 없음 (medium 이하) → 안내에 따라 직접 조치

기준 바꾸기: SECURITY_ESCALATE_MIN=critical (이 심각도 이상은 무조건 넘김), SECURITY_AUTO_MAX=high (자동 조치 상한)
"""
from __future__ import annotations

import os

from .findings import SEVERITIES
from .store import row_fix

RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}   # low 0 … critical 3
# 규칙 기반이라도 서비스 동작이 바뀔 수 있어 자동 적용하지 않는 규칙
NEEDS_APPROVAL = ("DEPS-", "SECRET-HARDCODED", "CONFIG-CORS")


def _sev(name: str, default: str) -> int:
    v = os.environ.get(name, default).strip().lower()
    return RANK.get(v, RANK[default])


def decide(row) -> str:
    sev = RANK.get(row["severity"], 0)
    if sev >= _sev("SECURITY_ESCALATE_MIN", "critical"):
        return "escalate"
    fix = row_fix(row)
    if not fix or not fix.automatic:
        return "escalate" if sev >= RANK["high"] else "manual"
    if fix.description.startswith("AI 제안") or row["rule"].startswith(NEEDS_APPROVAL):
        return "approve"
    return "auto" if sev <= _sev("SECURITY_AUTO_MAX", "high") else "approve"
