"""비밀정보 노출 — 키 · 토큰 · 비밀번호 하드코딩, .env 추적 여부."""
from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

from ..findings import Edit, Finding, Fix, read_lines
from ..walk import iter_files, os_import_edit_line, parse_python

TOKEN_RULES = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "SECRET-AWS-KEY", "critical", "AWS 액세스 키"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "SECRET-PRIVATE-KEY", "critical", "개인 키 파일 내용"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "SECRET-GITHUB-TOKEN", "critical", "GitHub 토큰"),
    (re.compile(r"\bxox[bpas]-[A-Za-z0-9-]{10,}\b"), "SECRET-SLACK-TOKEN", "high", "Slack 토큰"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "SECRET-GOOGLE-KEY", "high", "Google API 키"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,}\b"), "SECRET-AI-KEY", "critical", "OpenAI/Anthropic API 키"),
]
NAME_RX = re.compile(r"(passw(or)?d|pwd|secret|api_?key|access_?key|private_?key|token|client_secret)", re.I)
PLACEHOLDER_RX = re.compile(r"^(|x+|\*+|changeme|change_me|your[_-].*|<.*>|\$\{.*\}|dummy|test|example|placeholder|none|null|todo)$", re.I)
TEXT_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
                 ".env", ".txt", ".md", ".html", ".sh", ".ps1", ".bat", ".pem", ".key", ".conf")


def mask(value: str) -> str:
    return value[:4] + "****" if len(value) > 4 else "****"


def _python_assignments(service: str, path: Path, rel: str) -> list[Finding]:
    """NAME = "리터럴" 형태의 비밀번호/키 대입 → os.environ.get 패치."""
    tree = parse_python(path)
    if tree is None:
        return []
    lines = read_lines(path)
    import_line = os_import_edit_line(tree, lines)
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None for t in targets]
        name = next((n for n in names if n and NAME_RX.search(n)), None)
        value = node.value.value
        if not name or name.upper().endswith(("_URL", "_URI", "_ENDPOINT", "_PATH", "_HEADER", "_NAME"))                 or re.match(r"^(https?://|/|\.)", value)                 or len(value) < 6 or PLACEHOLDER_RX.match(value) or " " in value or node.lineno != node.end_lineno:
            continue
        line = lines[node.lineno - 1]
        literal = line[node.value.col_offset:node.value.end_col_offset]
        env = name.upper()
        edits = [Edit(rel, node.lineno, line, line.replace(literal, f'os.environ.get("{env}", "")', 1))]
        if import_line and import_line != node.lineno:
            edits.append(Edit(rel, import_line, lines[import_line - 1], lines[import_line - 1] + "\nimport os"))
        elif import_line is None and "import os" not in "\n".join(lines):
            edits = []   # import os 를 넣을 위치를 못 찾으면 수동 조치
        out.append(Finding(
            service, "secrets", "SECRET-HARDCODED", "high", f"비밀값 하드코딩 ({name})", rel, node.lineno,
            f"소스에 비밀값이 그대로 있습니다. 저장소에 올라간 값은 이미 노출된 것으로 보고 교체한 뒤 환경변수 {env} 로 옮기세요.",
            f"{name} = {mask(value)}",
            Fix(f"환경변수 {env} 에서 읽도록 변경 (값은 .env 등에 따로 설정)", edits)))
    return out


def _git_tracked(root: Path, rel: str) -> bool:
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "--error-unmatch", rel],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _git_ignored(root: Path, rel: str) -> bool:
    try:
        return subprocess.run(["git", "-C", str(root), "check-ignore", "-q", rel],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _env_files(service: str, root: Path) -> list[Finding]:
    out = []
    env = root / ".env"
    if not env.exists():
        return out
    gitignore = root / ".gitignore"
    ignored = gitignore.exists() and any(l.strip() in (".env", "/.env", "*.env", ".env*") for l in read_lines(gitignore))
    if _git_tracked(root, ".env"):
        out.append(Finding(service, "secrets", "SECRET-ENV-TRACKED", "critical", ".env 가 git 에 커밋됨", ".env", 1,
                           "git rm --cached .env 로 추적을 끊고, 들어 있던 키는 모두 교체하세요 (이력에 남아 있음).",
                           ".env", Fix("수동 조치: git rm --cached .env 후 키 교체")))
    if not ignored:
        edits = [Edit(".gitignore", 0, "", ".env")]
        out.append(Finding(service, "secrets", "SECRET-ENV-NOT-IGNORED", "medium", ".env 가 .gitignore 에 없음",
                           ".gitignore", 0, "실수로 커밋될 수 있습니다.", ".env", Fix(".gitignore 에 .env 추가", edits)))
    return out


def scan(service: str, root: Path) -> list[Finding]:
    out: list[Finding] = []
    for path, rel in iter_files(root, TEXT_SUFFIXES):
        if path.name.endswith((".lock", "-lock.json")) or path.name == ".env":
            continue
        for i, line in enumerate(read_lines(path), 1):
            for rx, rule, sev, title in TOKEN_RULES:
                m = rx.search(line)
                if m:
                    if _git_ignored(root, rel):
                        out.append(Finding(service, "secrets", rule, "low", f"{title} (로컬 전용 파일)", rel, i,
                                           ".gitignore 로 제외돼 커밋되지는 않습니다. 운영 서버 외 복사본이 없는지, 권한이 제한됐는지 확인하세요.",
                                           mask(m.group(0))))
                    else:
                        out.append(Finding(service, "secrets", rule, sev, f"{title} 노출", rel, i,
                                           "키를 즉시 폐기·재발급하고 환경변수나 비밀 저장소로 옮기세요.", mask(m.group(0)),
                                           Fix("수동 조치: 키 폐기 후 재발급")))
        if path.suffix == ".py":
            out += _python_assignments(service, path, rel)
    return out + _env_files(service, root)
