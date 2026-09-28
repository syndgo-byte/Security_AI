"""코드 취약점 (SAST) — Python 은 AST, JS/TS 는 패턴."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Edit, Finding, Fix, read_lines
from ..walk import call_name, is_true, iter_files, kwarg, parse_python

SQL_CALLS = ("execute", "executemany", "executescript", "raw", "text")
JS_RULES = [
    (re.compile(r"\.innerHTML\s*=(?!=)"), "SAST-JS-INNERHTML", "medium", "innerHTML 직접 대입 (XSS)",
     "사용자 입력이 섞이면 스크립트가 실행됩니다. textContent 를 쓰거나 값을 이스케이프하세요."),
    (re.compile(r"dangerouslySetInnerHTML"), "SAST-JS-DANGEROUS-HTML", "medium", "dangerouslySetInnerHTML 사용 (XSS)",
     "신뢰할 수 없는 HTML 이면 DOMPurify 등으로 정화한 뒤 넣으세요."),
    (re.compile(r"(?<![\w.])eval\s*\("), "SAST-JS-EVAL", "high", "eval() 사용 (코드 실행)",
     "문자열을 코드로 실행합니다. JSON.parse 나 명시적 분기로 바꾸세요."),
    (re.compile(r"document\.write\s*\("), "SAST-JS-DOCWRITE", "low", "document.write 사용",
     "DOM API(createElement/textContent)로 바꾸세요."),
]


def _is_dynamic_sql(node) -> bool:
    """f-string · % · .format · + 로 만든 문자열 (파라미터 바인딩이 아닌 SQL)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return isinstance(node.left, (ast.Constant, ast.JoinedStr, ast.BinOp)) or isinstance(node.right, ast.Constant)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _python(service: str, path: Path, rel: str) -> list[Finding]:
    tree = parse_python(path)
    if tree is None:
        return []
    lines = read_lines(path)
    out: list[Finding] = []

    def add(node, rule, sev, title, detail, fix=None):
        out.append(Finding(service, "sast", rule, sev, title, rel, node.lineno, detail,
                           lines[node.lineno - 1].strip()[:200], fix))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node)
        last = name.rsplit(".", 1)[-1]
        line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""

        if name in ("eval", "exec"):
            add(node, "SAST-PY-EVAL", "high", f"{name}() 사용 (임의 코드 실행)",
                "외부 입력이 들어가면 서버에서 임의 코드가 실행됩니다. ast.literal_eval 이나 명시적 분기로 바꾸세요.")
        elif name in ("os.system", "os.popen") or (name.startswith("subprocess.") and is_true(kwarg(node, "shell"))):
            add(node, "SAST-PY-SHELL", "high", "셸 명령 실행 (명령 주입)",
                "문자열 명령을 셸로 실행합니다. subprocess.run([...], shell=False) 처럼 인자 목록으로 넘기세요.")
        elif name in ("pickle.load", "pickle.loads", "marshal.loads", "shelve.open"):
            add(node, "SAST-PY-PICKLE", "medium", "pickle 역직렬화",
                "신뢰할 수 없는 데이터를 pickle 로 읽으면 코드가 실행됩니다. JSON 등으로 바꾸세요.")
        elif name == "yaml.load" and kwarg(node, "Loader") is None and line.count("yaml.load(") == 1:
            add(node, "SAST-PY-YAML", "high", "yaml.load (안전하지 않은 로더)",
                "임의 객체가 생성될 수 있습니다. yaml.safe_load 를 쓰세요.",
                Fix("yaml.load → yaml.safe_load", [Edit(rel, node.lineno, line, line.replace("yaml.load(", "yaml.safe_load("))]))
        elif last in SQL_CALLS and node.args and _is_dynamic_sql(node.args[0]):
            head = ast.unparse(node.args[0]).lstrip("f'\"").upper()
            if head.startswith(("ALTER TABLE", "CREATE TABLE", "CREATE INDEX", "DROP TABLE", "PRAGMA")):
                add(node, "SAST-PY-SQL-DDL", "low", "동적 DDL (스키마 변경문 조립)",
                    "마이그레이션용 DDL 로 보입니다. 끼워 넣는 테이블/컬럼명이 코드 상수뿐인지 확인하세요.")
            elif len(node.args) > 1 or node.keywords:
                # 자리표시자('?' * n)나 컬럼명만 조립하고 값은 바인딩으로 넘기는 흔한 패턴 — 검토만 권고
                add(node, "SAST-PY-SQL-DYNAMIC", "low", "동적 SQL (바인딩 병행, 검토 필요)",
                    "값은 파라미터로 넘기고 있습니다. 문자열에 끼운 부분이 자리표시자·고정 컬럼명뿐인지만 확인하세요.")
            else:
                add(node, "SAST-PY-SQLI", "high", "문자열로 조립한 SQL (SQL 인젝션)",
                    "값을 문자열에 직접 끼워 넣었습니다. execute(\"... WHERE id = ?\", (값,)) 처럼 파라미터 바인딩을 쓰세요.")
        elif name.split(".")[0] in ("requests", "httpx", "session", "client") and kwarg(node, "verify") is not None \
                and isinstance(kwarg(node, "verify"), ast.Constant) and kwarg(node, "verify").value is False:
            fixed = re.sub(r",\s*verify\s*=\s*False", "", line)
            fix = Fix("verify=False 제거 (인증서 검증 켜기)", [Edit(rel, node.lineno, line, fixed)]) if fixed != line else None
            add(node, "SAST-PY-TLS-VERIFY", "medium", "TLS 인증서 검증 끔 (verify=False)",
                "중간자 공격에 노출됩니다. 사설 인증서면 verify='ca.pem' 으로 지정하세요.", fix)
        elif name in ("hashlib.md5", "hashlib.sha1"):
            add(node, "SAST-PY-WEAK-HASH", "low", f"약한 해시 ({last})",
                "비밀번호 · 서명 용도라면 argon2/bcrypt 또는 sha256 이상을 쓰세요. 단순 체크섬이면 무시해도 됩니다.")
        elif name == "tempfile.mktemp":
            add(node, "SAST-PY-MKTEMP", "medium", "tempfile.mktemp (경쟁 조건)",
                "파일명만 만들고 파일은 만들지 않아 가로채기가 가능합니다. NamedTemporaryFile/mkstemp 를 쓰세요.",
                Fix("mktemp → mkstemp 는 반환값이 달라 수동 수정 필요"))
    return out


def _js(service: str, path: Path, rel: str) -> list[Finding]:
    out = []
    for i, line in enumerate(read_lines(path), 1):
        if line.lstrip().startswith("//"):
            continue
        for rx, rule, sev, title, detail in JS_RULES:
            if rx.search(line):
                out.append(Finding(service, "sast", rule, sev, title, rel, i, detail, line.strip()[:200]))
    return out


def scan(service: str, root: Path) -> list[Finding]:
    out: list[Finding] = []
    for path, rel in iter_files(root, (".py", ".js", ".jsx", ".ts", ".tsx", ".html")):
        if path.suffix == ".py":
            out += _python(service, path, rel)
        elif not path.name.endswith(".min.js"):
            out += _js(service, path, rel)
    return out
