"""설정 · 개인정보 점검 — 디버그 모드, CORS, 쿠키, 로그, 고유식별정보 암호화 (개인정보보호법)."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Edit, Finding, Fix, read_lines
from ..walk import call_name, is_true, iter_files, kwarg, os_import_edit_line, parse_python

# 개인정보보호법 제24조 · 안전성 확보조치 기준 제7조: 고유식별정보(주민 · 여권 · 운전면허 · 외국인등록번호)는 암호화 저장.
# 카드 · 계좌번호는 신용정보법/전자금융 기준상 암호화 대상.
PII_RX = re.compile(r"(rrn|resident|jumin|ssn|passport|driver_?license|foreigner|card_?no|card_?number|account_?no|bank_?account)", re.I)
ENCRYPTED_RX = re.compile(r"(encrypt|cipher|hash|fernet|aes|_enc\b|_hash\b|masked|last4)", re.I)
LOG_CALLS = ("print", "logger.info", "logger.debug", "logger.warning", "logger.error", "logging.info",
             "logging.debug", "log.info", "log.debug")


def _python(service: str, path: Path, rel: str) -> list[Finding]:
    tree = parse_python(path)
    if tree is None:
        return []
    lines = read_lines(path)
    out: list[Finding] = []

    def add(lineno, rule, sev, title, detail, fix=None):
        out.append(Finding(service, "config", rule, sev, title, rel, lineno, detail, lines[lineno - 1].strip()[:200], fix))

    import_line = os_import_edit_line(tree, lines)
    has_os = import_line is None and re.search(r"^\s*import os\b", "\n".join(lines), re.M)

    def env_fix(lineno, old, new, desc):
        line = lines[lineno - 1]
        if old not in line:
            return Fix("수동 조치: " + desc)
        edits = [Edit(rel, lineno, line, line.replace(old, new, 1))]
        if import_line and import_line != lineno:
            edits.append(Edit(rel, import_line, lines[import_line - 1], lines[import_line - 1] + "\nimport os"))
        elif not has_os:
            return Fix("수동 조치: " + desc)
        return Fix(desc, edits)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and is_true(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "DEBUG":
                    add(node.lineno, "CONFIG-DEBUG", "medium", "DEBUG = True 고정",
                        "운영에서 오류 화면에 코드와 설정이 노출됩니다. 환경변수로 켜고 끄세요.",
                        env_fix(node.lineno, "True", 'os.environ.get("DEBUG") == "1"', "DEBUG 를 환경변수로 제어"))
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node)
        last = name.rsplit(".", 1)[-1]
        if last == "run" and is_true(kwarg(node, "debug")):
            add(node.lineno, "CONFIG-DEBUG-RUN", "high", "debug=True 로 서버 실행",
                "Flask/Werkzeug 디버거가 켜지면 원격 코드 실행이 가능합니다.",
                env_fix(node.lineno, "debug=True", 'debug=os.environ.get("DEBUG") == "1"', "debug 를 환경변수로 제어"))
        elif last == "add_middleware" or name.endswith("CORS"):
            origins = kwarg(node, "allow_origins") or kwarg(node, "origins")
            star = isinstance(origins, (ast.List, ast.Tuple)) and any(
                isinstance(e, ast.Constant) and e.value == "*" for e in origins.elts) \
                or isinstance(origins, ast.Constant) and origins.value == "*"
            if star:
                creds = is_true(kwarg(node, "allow_credentials")) or is_true(kwarg(node, "supports_credentials"))
                add(node.lineno, "CONFIG-CORS-WILDCARD", "high" if creds else "medium",
                    "CORS 모든 출처 허용" + (" + 자격증명" if creds else ""),
                    "허용 출처를 실제 프런트 도메인 목록으로 좁히세요." +
                    (" 자격증명까지 허용하면 다른 사이트가 로그인 세션으로 API 를 호출할 수 있습니다." if creds else ""))
        elif last == "set_cookie":
            # 없거나 상수 False 일 때만. secure=request.url.scheme == "https" 같은 조건식은 의도된 설정으로 본다
            missing = [k for k in ("secure", "httponly") if kwarg(node, k) is None
                       or (isinstance(kwarg(node, k), ast.Constant) and not kwarg(node, k).value)]
            if missing and not any(k.arg is None for k in node.keywords):
                add(node.lineno, "CONFIG-COOKIE-FLAGS", "medium", f"쿠키 보안 속성 누락 ({', '.join(missing)})",
                    "세션 · 인증 쿠키라면 secure=True, httponly=True, samesite='lax' 이상을 지정하세요.")
        elif name in LOG_CALLS:
            text = lines[node.lineno - 1]
            if re.search(r"passw(or)?d|pwd|secret|token", text, re.I) and any(
                    isinstance(a, (ast.JoinedStr, ast.Name, ast.BinOp)) for a in node.args):
                add(node.lineno, "CONFIG-LOG-SECRET", "medium", "로그에 비밀번호/토큰 출력 의심",
                    "개인정보 안전성 확보조치 기준상 인증정보는 로그에 남기면 안 됩니다. 값을 빼거나 마스킹하세요.")
    out += _pii_columns(service, tree, lines, rel)
    return out


def _pii_columns(service: str, tree: ast.AST, lines: list[str], rel: str) -> list[Finding]:
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        target = node.targets[0] if isinstance(node, ast.Assign) else node.target
        if not isinstance(target, ast.Name) or not isinstance(node.value, ast.Call):
            continue
        col = target.id
        if call_name(node.value).rsplit(".", 1)[-1] not in ("Column", "mapped_column"):
            continue
        text = lines[node.lineno - 1]
        if PII_RX.search(col) and not ENCRYPTED_RX.search(col) and not ENCRYPTED_RX.search(text) \
                and re.search(r"\b(String|Text|VARCHAR|Unicode)\b", text):
            out.append(Finding(
                service, "config", "PIPA-UNIQUE-ID-PLAINTEXT", "high", f"고유식별정보 평문 저장 의심 ({col})", rel,
                node.lineno,
                "개인정보보호법 제24조 · 안전성 확보조치 기준 제7조: 주민등록 · 여권 · 운전면허 · 외국인등록번호는 "
                "암호화해 저장해야 합니다 (카드 · 계좌번호도 암호화 권장). 저장 시 AES 등으로 암호화하고, 컬럼명에 _enc 를 붙여 구분하세요.",
                text.strip()[:200], Fix("수동 조치: 암호화 저장 및 기존 데이터 마이그레이션")))
    return out


def scan(service: str, root: Path) -> list[Finding]:
    out: list[Finding] = []
    for path, rel in iter_files(root, (".py",)):
        if "/tests/" in f"/{rel}" or path.name.startswith("test_"):
            continue
        out += _python(service, path, rel)
    return out
