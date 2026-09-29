"""웹 가벼운 점검 — 실행 중인 서비스에 GET 몇 번만 보낸다 (공격 페이로드 없음).

보안 헤더 · 쿠키 속성 · CORS · HTTPS · 노출 경로(.env, .git) · 인증서 만료.
결과는 코드가 아니라 응답 기준이라 자동 수정 없이 조치 안내만 붙인다.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from ..findings import Finding, Fix

TIMEOUT = 10
PROBE_ORIGIN = "https://security-probe.invalid"
UA = "MCP-Hub-Security/0.1 (+passive check)"
LOCAL = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def fetch(url: str, headers: dict | None = None, follow: bool = True, limit: int = 65536):
    """(상태, 헤더(소문자 키 → 값 목록), 본문 앞부분, 최종 주소). 연결 실패면 OSError."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        r = opener.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        r = e
    with r:
        hdrs: dict[str, list[str]] = {}
        for k, v in r.headers.items():
            hdrs.setdefault(k.lower(), []).append(v)
        return r.status if hasattr(r, "status") else r.code, hdrs, r.read(limit), r.geturl()


def _h(hdrs, name) -> str:
    return ", ".join(hdrs.get(name, []))


def _f(service, rule, severity, title, url, detail, evidence, how) -> Finding:
    return Finding(service, "web", rule, severity, title, url, 0, detail, evidence, Fix("수동 조치: " + how))


def check_headers(service: str, url: str, hdrs: dict, body: bytes) -> list[Finding]:
    out = []
    https = url.startswith("https://")
    html = "html" in _h(hdrs, "content-type").lower() or body.lstrip()[:15].lower().startswith((b"<!doctype", b"<html"))
    if "nosniff" not in _h(hdrs, "x-content-type-options").lower():
        out.append(_f(service, "WEB-HDR-NOSNIFF", "low", "X-Content-Type-Options 누락", url,
                      "브라우저가 응답 형식을 추측해 스크립트로 실행할 수 있습니다.", "x-content-type-options",
                      "응답 헤더에 X-Content-Type-Options: nosniff"))
    if html:
        csp = _h(hdrs, "content-security-policy")
        if not csp:
            out.append(_f(service, "WEB-HDR-CSP", "medium", "Content-Security-Policy 누락", url,
                          "XSS 가 생겼을 때 막아줄 마지막 방어선이 없습니다.", "content-security-policy",
                          "Content-Security-Policy: default-src 'self' 부터 시작해 필요한 출처만 추가"))
        if not _h(hdrs, "x-frame-options") and "frame-ancestors" not in csp:
            out.append(_f(service, "WEB-HDR-FRAME", "low", "클릭재킹 방지 헤더 누락", url,
                          "다른 사이트가 이 페이지를 iframe 으로 덮어씌울 수 있습니다.", "x-frame-options",
                          "X-Frame-Options: DENY 또는 CSP frame-ancestors 'none'"))
    if https and not _h(hdrs, "strict-transport-security"):
        out.append(_f(service, "WEB-HDR-HSTS", "medium", "HSTS 누락", url,
                      "첫 접속을 http 로 가로채 다운그레이드할 수 있습니다.", "strict-transport-security",
                      "Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    for name in ("server", "x-powered-by"):
        v = _h(hdrs, name)
        if re.search(r"\d+\.\d+", v):
            out.append(_f(service, "WEB-HDR-VERSION", "low", f"{name} 헤더에 버전 노출", url,
                          "공격자가 알려진 취약 버전을 바로 고를 수 있습니다.", f"{name}: {v[:80]}",
                          f"{name} 헤더 제거 또는 버전 숨기기"))
    for c in hdrs.get("set-cookie", []):
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        miss = [a for a, ok in (("HttpOnly", "httponly" in low), ("SameSite", "samesite" in low),
                                ("Secure", "secure" in low or not https)) if not ok]
        if miss:
            out.append(_f(service, "WEB-COOKIE", "medium", f"쿠키 {name} 속성 누락: {', '.join(miss)}", url,
                          "세션 쿠키가 스크립트로 읽히거나 다른 사이트 요청에 실려 갈 수 있습니다.", f"set-cookie: {name}",
                          f"쿠키 설정에 {'; '.join(miss)} 추가"))
    return out


def check_cors(service: str, url: str) -> list[Finding]:
    _, hdrs, _, _ = fetch(url, {"Origin": PROBE_ORIGIN})
    allow, cred = _h(hdrs, "access-control-allow-origin"), _h(hdrs, "access-control-allow-credentials").lower()
    if allow == PROBE_ORIGIN and cred == "true":
        return [_f(service, "WEB-CORS-CRED", "high", "아무 출처나 허용 + 인증정보 허용 (CORS)", url,
                   "어떤 사이트든 로그인한 사용자의 권한으로 이 API 를 읽을 수 있습니다.", f"ACAO: {allow}; ACAC: true",
                   "허용 출처를 고정 목록으로 제한")]
    if allow == PROBE_ORIGIN:
        return [_f(service, "WEB-CORS-REFLECT", "medium", "요청 출처를 그대로 허용 (CORS)", url,
                   "Origin 헤더를 검사 없이 되돌려 줍니다.", f"ACAO: {allow}", "허용 출처를 고정 목록으로 제한")]
    return []


# 경로, 규칙, 심각도, 제목, 실제 노출 판정 (SPA 가 모든 경로에 index.html 을 주는 경우를 거른다)
EXPOSED = [
    ("/.env", "WEB-EXPOSED-ENV", "critical", ".env 파일 노출",
     lambda b: b"<html" not in b.lower() and re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=", b) is not None),
    ("/.git/HEAD", "WEB-EXPOSED-GIT", "high", ".git 폴더 노출", lambda b: b.startswith(b"ref: ")),
    ("/openapi.json", "WEB-EXPOSED-OPENAPI", "low", "API 명세 공개", lambda b: b'"openapi"' in b[:200]),
]


def check_exposed(service: str, url: str) -> list[Finding]:
    out = []
    base = url if url.endswith("/") else url + "/"
    for path, rule, sev, title, real in EXPOSED:
        target = urljoin(base, path.lstrip("/"))
        try:
            status, _, body, _ = fetch(target, follow=False, limit=4096)
        except OSError:
            continue
        if status == 200 and real(body):
            out.append(_f(service, rule, sev, title, target, "누구나 받아갈 수 있는 경로입니다.", path,
                          "웹 서버에서 해당 경로 차단, 노출된 키가 있으면 폐기 후 재발급"))
    return out


def check_tls(service: str, url: str, warn_days: int = 30) -> list[Finding]:
    u = urlsplit(url)
    host, port = u.hostname, u.port or 443
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s, \
                ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
            cert = t.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return [_f(service, "WEB-TLS-INVALID", "high", "인증서 검증 실패", url, str(e.verify_message or e)[:200],
                   host, "유효한 인증서로 교체 (호스트 이름 · 체인 확인)")]
    except OSError:
        return []
    left = (datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
            - datetime.now(timezone.utc)).days
    if left < warn_days:
        sev = "critical" if left < 0 else "high" if left < 14 else "medium"
        return [_f(service, "WEB-TLS-EXPIRY", sev, f"인증서 만료 {'됨' if left < 0 else f'{left}일 전'}", url,
                   f"만료일 {cert['notAfter']}", host, "인증서 갱신 (자동 갱신 설정 확인)")]
    return []


def scan_site(service: str, url: str) -> list[Finding]:
    """사이트 하나 점검. 첫 요청부터 연결이 안 되면 OSError (이전 결과를 지우지 않도록)."""
    status, hdrs, body, final = fetch(url)
    out = []
    host = urlsplit(url).hostname or ""
    if url.startswith("http://") and host not in LOCAL:
        out.append(_f(service, "WEB-NO-HTTPS", "high", "HTTPS 미사용", url,
                      "주고받는 내용 · 쿠키가 평문으로 오갑니다.", url, "HTTPS 적용 후 http 는 https 로 리다이렉트"))
    elif url.startswith("https://"):
        out += check_tls(service, url)
    out += check_headers(service, final, hdrs, body)
    try:
        out += check_cors(service, url)
    except OSError:
        pass
    out += check_exposed(service, url)
    return list({f.id: f for f in out}.values())


def scan(sites: dict[str, list[str]], only: str | None = None) -> tuple[dict[str, list[Finding]], list[str]]:
    per_service, errors = {}, []
    for service, urls in sites.items():
        if only and service != only:
            continue
        found, ok = [], False
        for url in urls:
            try:
                found += scan_site(service, url)
                ok = True
            except OSError as e:
                errors.append(f"{service} {url}: 접속 실패 ({e})")
        if ok:
            per_service[service] = found
    return per_service, errors
