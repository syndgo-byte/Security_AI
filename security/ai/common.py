"""AI 기능 공통 — 코드 전송 동의, 비밀값 가리기, 모델 간 합의."""
from __future__ import annotations

import os
import re
from collections import Counter

from ..findings import SEVERITIES
from ..scanners.secrets import NAME_RX, TOKEN_RULES, mask

ASSIGN_RX = re.compile(r"""(?P<head>\b\w*(?:%s)\w*\b["']?\s*[:=]\s*)(?P<q>["'])(?P<val>[^"'\s]{6,})(?P=q)""" % NAME_RX.pattern,
                       re.I)


class ConsentError(Exception):
    pass


def require_code_consent(allow_code: bool) -> None:
    if not (allow_code or os.environ.get("SECURITY_AI_SEND_CODE") == "1"):
        raise ConsentError("코드 일부를 외부 AI 모델로 보내야 합니다. allow_code=true(CLI --allow-code)로 동의하거나 "
                           "SECURITY_AI_SEND_CODE=1 을 설정하세요.")


def redact(text: str) -> str:
    """토큰 패턴과 `password = "..."` 형태의 값을 가린다 (줄 수·줄 번호는 그대로)."""
    for rx, *_ in TOKEN_RULES:
        text = rx.sub(lambda m: mask(m.group(0)), text)
    return ASSIGN_RX.sub(lambda m: f"{m['head']}{m['q']}{mask(m['val'])}{m['q']}", text)


def numbered(lines: list[str], start: int = 1) -> str:
    return "\n".join(f"{i}| {l}" for i, l in enumerate(lines, start))


def norm_severity(s) -> str:
    s = str(s or "").lower()
    return {"moderate": "medium", "info": "low", "informational": "low"}.get(s, s if s in SEVERITIES else "medium")


def consensus_severity(sevs: list[str], agreed: int, total: int) -> str:
    """가장 높은 심각도를 쓰되, 여러 모델 중 하나만 지목했으면 한 단계 낮춘다."""
    top = min((norm_severity(s) for s in sevs), key=SEVERITIES.index)
    if total >= 2 and agreed == 1:
        top = SEVERITIES[min(SEVERITIES.index(top) + 1, len(SEVERITIES) - 1)]
    return top


def majority(values: list[str]) -> str | None:
    if not values:
        return None
    (top, n), *rest = Counter(values).most_common()
    return top if not rest or rest[0][1] < n else None
