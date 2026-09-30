"""법정 기술조치 점검 — 「개인정보의 안전성 확보조치 기준」 중 기존 진단기가 못 보던 항목.

코드에서 "있어야 할 것이 없는지"를 본다. 정적 분석이라 없다는 증거일 뿐 위반 확정이 아니므로
제목에 '확인 필요'를 붙이고 심각도는 medium 이하로 둔다(확정 가능한 것만 high).

  LEGAL-LOG-NO-ACCESS-LOG     제8조①  웹 서비스인데 접속기록(감사 로그) 흔적이 없음
  LEGAL-LOG-RETENTION         제8조①  로그 보관 기간 설정이 1년 미만
  LEGAL-SESSION-NO-EXPIRY     제6조④  JWT 를 발급하는데 만료(exp)가 없음
  LEGAL-SESSION-LONG          제6조④  쿠키 max_age 가 30일 초과
  LEGAL-NO-MFA                제6조②  관리자 기능이 있는데 일회용 비밀번호 · 보안토큰 등 추가 인증 흔적이 없음
  LEGAL-PASSWORD-PLAIN        제7조①  비밀번호 필드가 있는데 일방향 해시 라이브러리를 안 씀
  LEGAL-PASSWORD-FAST-HASH    제7조①  비밀번호를 sha256 등 단순 해시로 저장 (솔트 · 반복 없음)
  LEGAL-PASSWORD-MINLEN       정보보호조치 지침 별표1 2.2.9  비밀번호 최소 길이 설정이 8 미만
  LEGAL-NO-LOGIN-LOCKOUT      전자금융감독규정 제34조의3②2호  로그인은 있는데 입력 오류 횟수 제한 흔적이 없음
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding, read_lines
from ..walk import iter_files

WEB_RX = re.compile(r"^\s*(?:from|import)\s+(fastapi|flask|django|starlette|aiohttp|bottle|tornado)\b|require\(['\"]express['\"]\)", re.M)
ACCESS_LOG_RX = re.compile(r"audit|access[_-]?log|login[_-]?(?:log|history|record)|activity[_-]?log|접속\s*기록|event[_-]?log", re.I)
RETENTION_RX = re.compile(r"(retention|keep)[_-]?days?\w*\s*[=:]\s*(\d+)", re.I)
TIMED_ROTATE_RX = re.compile(r"TimedRotatingFileHandler\s*\(([^)]*)\)", re.S)
ADMIN_RX = re.compile(r"""["']/admin\b|is_admin|require_admin|role\s*==\s*["']admin|admin_required""", re.I)
MFA_RX = re.compile(r"totp|pyotp|\botp\b|2fa|mfa|two[_-]?factor|webauthn|passkey|authenticator|일회용", re.I)
PW_FIELD_RX = re.compile(r"""password(?:_hash)?\s*=\s*(?:db\.)?(?:Column|Field)\(|password\s+(?:TEXT|VARCHAR)|["']password["']\s*:\s*(?:str|Field)""", re.I)
PW_HASH_RX = re.compile(r"bcrypt|argon2|pbkdf2|scrypt|passlib|werkzeug\.security|generate_password_hash|make_password|hash_password|get_password_hash", re.I)
FAST_HASH_RX = re.compile(r"hashlib\.(sha1|sha224|sha256|sha384|sha512|md5)\(\s*(?:\w+\.)?(?:password|passwd|pw)\b", re.I)
JWT_ENCODE_RX = re.compile(r"jwt\.encode\(")
COOKIE_AGE_RX = re.compile(r"max_age\s*=\s*([0-9*\s]+)")
PW_MINLEN_RX = re.compile(r"(?:password|passwd|pw)\w*?_?min(?:imum)?_?len(?:gth)?\s*[=:]\s*(\d+)"
                          r"|(?:password|passwd|pw)\w*\s*[:=][^\n]{0,60}?min_length\s*=\s*(\d+)", re.I)
LOGIN_RX = re.compile(r"""def\s+(?:login|signin|sign_in|authenticate)\b|["']/(?:auth/)?(?:login|signin)\b""", re.I)
LOCKOUT_RX = re.compile(r"fail(?:ed)?_?(?:count|attempts?|login)|login_?attempts?|lockout|locked_?until|"
                        r"max_?attempts|rate_?limit|slowapi|limiter\.limit|too\s+many|login_?lock|throttl|brute", re.I)
DAY = 86400


def _files(root: Path):
    for path, rel in iter_files(root, (".py", ".js", ".ts")):
        if any(p in ("tests", "test", "__tests__") or p.startswith("test_") for p in rel.split("/")):
            continue
        yield path, rel


def _eval_int(expr: str) -> int | None:
    expr = expr.strip()
    if not re.fullmatch(r"[0-9*\s]+", expr) or not expr:
        return None
    n = 1
    for part in expr.split("*"):
        part = part.strip()
        if not part.isdigit():
            return None
        n *= int(part)
    return n


def scan(service: str, root: Path) -> list[Finding]:
    root = Path(root)
    out: list[Finding] = []
    files = []
    for path, rel in _files(root):
        try:
            files.append((rel, path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue

    def add(rel, lineno, rule, sev, title, detail):
        lines = next((t for r, t in files if r == rel), "").splitlines()
        ev = lines[lineno - 1].strip()[:200] if 0 < lineno <= len(lines) else ""
        out.append(Finding(service, "legal", rule, sev, title, rel, lineno, detail, ev, None))

    def line_of(text, m):
        return text.count("\n", 0, m.start()) + 1

    web = next(((r, t, m) for r, t in files if (m := WEB_RX.search(t))), None)
    alltext = "\n".join(t for _, t in files)

    # 제8조① 접속기록
    if web and not ACCESS_LOG_RX.search(alltext):
        rel, text, m = web
        add(rel, line_of(text, m), "LEGAL-LOG-NO-ACCESS-LOG", "medium", "접속기록 보관 흔적 없음 (확인 필요)",
            "안전성 확보조치 기준 제8조①: 개인정보처리시스템 접속기록을 1년(5만명 이상 · 고유식별정보 · 민감정보는 2년) 이상 "
            "보관해야 합니다. 로그인 · 조회 · 다운로드를 남기는 감사 로그가 코드에서 보이지 않습니다.")
    for rel, text in files:
        for m in RETENTION_RX.finditer(text):
            if "log" in text[max(0, m.start() - 120):m.end()].lower() and int(m.group(2)) < 365:
                add(rel, line_of(text, m), "LEGAL-LOG-RETENTION", "medium", f"로그 보관 기간 {m.group(2)}일 (1년 미만)",
                    "안전성 확보조치 기준 제8조①: 접속기록은 최소 1년 보관해야 합니다.")
        for m in TIMED_ROTATE_RX.finditer(text):
            args = m.group(1)
            bc = re.search(r"backupCount\s*=\s*(\d+)", args)
            when = re.search(r"when\s*=\s*[\"'](\w+)[\"']|,\s*[\"'](\w+)[\"']", args)
            unit = (when.group(1) or when.group(2)) if when else "h"
            if bc and unit.lower() in ("d", "midnight") and int(bc.group(1)) < 365:
                add(rel, line_of(text, m), "LEGAL-LOG-RETENTION", "medium", f"로그 일별 회전 {bc.group(1)}개만 보관 (1년 미만)",
                    "안전성 확보조치 기준 제8조①: 접속기록은 최소 1년 보관해야 합니다. backupCount 를 365 이상으로.")

    # 제6조④ 자동 접속 차단 (세션 만료)
    for rel, text in files:
        if rel.endswith(".py") and JWT_ENCODE_RX.search(text) and not re.search(r"""["']exp["']|\bexp\s*=""", text):
            m = JWT_ENCODE_RX.search(text)
            add(rel, line_of(text, m), "LEGAL-SESSION-NO-EXPIRY", "medium", "JWT 만료(exp) 없음 (확인 필요)",
                "안전성 확보조치 기준 제6조④: 일정 시간 업무처리가 없으면 접속이 자동으로 차단되어야 합니다. "
                "만료 없는 토큰은 영구히 유효합니다. payload 에 exp 를 넣으세요.")
        for m in COOKIE_AGE_RX.finditer(text):
            n = _eval_int(m.group(1))
            if n and n > 30 * DAY:
                add(rel, line_of(text, m), "LEGAL-SESSION-LONG", "low", f"쿠키 유효기간 {n // DAY}일 (30일 초과)",
                    "안전성 확보조치 기준 제6조④: 세션 유지 기간이 지나치게 길면 자동 차단 취지에 어긋납니다. "
                    "자동 로그인 용도라면 별도 재인증을 두세요.")

    # 제6조② 외부 접속 추가 인증
    admin = next(((r, t, m) for r, t in files if (m := ADMIN_RX.search(t))), None)
    if admin and not MFA_RX.search(alltext):
        rel, text, m = admin
        add(rel, line_of(text, m), "LEGAL-NO-MFA", "medium", "관리자 추가 인증(OTP 등) 흔적 없음 (확인 필요)",
            "안전성 확보조치 기준 제6조②: 권한 있는 자가 외부에서 개인정보처리시스템에 접속할 때는 인증서 · 보안토큰 · "
            "일회용 비밀번호 등 안전한 인증수단(또는 VPN)을 적용해야 합니다. 관리자 기능은 있으나 OTP/2단계 인증 코드가 보이지 않습니다. "
            "VPN · IP 제한으로 대체했다면 무시하세요.")

    # 제7조① 비밀번호 일방향 암호화
    pw = next(((r, t, m) for r, t in files if (m := PW_FIELD_RX.search(t))), None)
    if pw and not PW_HASH_RX.search(alltext):
        rel, text, m = pw
        add(rel, line_of(text, m), "LEGAL-PASSWORD-PLAIN", "medium", "비밀번호 해시 라이브러리 미사용 (확인 필요)",
            "안전성 확보조치 기준 제7조①: 비밀번호는 복호화되지 않도록 일방향 암호화하여 저장해야 합니다. "
            "비밀번호 필드는 있으나 bcrypt · argon2 · pbkdf2 · scrypt 사용이 보이지 않습니다.")
    for rel, text in files:
        for m in FAST_HASH_RX.finditer(text):
            add(rel, line_of(text, m), "LEGAL-PASSWORD-FAST-HASH", "medium", f"비밀번호를 {m.group(1)} 단순 해시로 처리",
                "안전성 확보조치 기준 제7조①: 솔트 · 반복이 없는 빠른 해시는 사전 대입에 약합니다. "
                "bcrypt · argon2 · pbkdf2(hashlib.pbkdf2_hmac) 를 쓰세요.")
        for m in PW_MINLEN_RX.finditer(text):
            n = int(m.group(1) or m.group(2))
            if n < 8:
                add(rel, line_of(text, m), "LEGAL-PASSWORD-MINLEN", "medium", f"비밀번호 최소 길이 {n}자 (8자 미만)",
                    "정보보호조치에 관한 지침 별표1 2.2.9: 관리자 계정 비밀번호는 8자리 이상. "
                    "이용자 비밀번호도 제3자가 유추하기 어렵게(전자금융감독규정 제34조의3②1호) 8자 이상 + 조합 규칙을 권장합니다.")

    # 전자금융감독규정 제34조의3②2호
    login = next(((r, t, m) for r, t in files if (m := LOGIN_RX.search(t))), None)
    if login and not LOCKOUT_RX.search(alltext):
        rel, text, m = login
        add(rel, line_of(text, m), "LEGAL-NO-LOGIN-LOCKOUT", "medium", "로그인 오류 횟수 제한 흔적 없음 (확인 필요)",
            "비밀번호를 계속 틀려도 막지 않으면 대입 공격에 무방비입니다. 전자금융감독규정 제34조의3②2호는 정한 횟수 이상 "
            "틀리면 즉시 중지 후 본인확인을 요구합니다. 실패 횟수를 세어 잠그거나 요청 속도 제한을 두세요.")
    return out

