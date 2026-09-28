"""대상 저장소 파일 순회 (빌드 산출물 · 백업 · 가상환경 제외)."""
from __future__ import annotations

import ast
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build", ".handoff",
    ".claude", ".pytest_cache", ".mypy_cache", ".security_backups", "site-packages", ".next", "coverage",
}
MAX_BYTES = 1_000_000


def iter_files(root: Path, suffixes: tuple[str, ...] | None = None):
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS or part.endswith(".egg-info") or part.lower().startswith("backup")
               for part in rel.parts[:-1]):
            continue
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            continue
        if suffixes and path.suffix.lower() not in suffixes and path.name not in suffixes:
            continue
        yield path, rel.as_posix()


def parse_python(path: Path) -> ast.AST | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return None


def call_name(node: ast.Call) -> str:
    """ast.Call 의 호출 대상 이름 ('subprocess.run', 'eval', 'cursor.execute' 등)."""
    parts = []
    f = node.func
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def kwarg(node: ast.Call, name: str):
    return next((k.value for k in node.keywords if k.arg == name), None)


def is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def os_import_edit_line(tree: ast.AST, lines: list[str]):
    """`import os` 가 없으면 넣을 위치(마지막 최상위 import 줄)를 돌려준다. 이미 있으면 None."""
    last = None
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Import) and any(a.name == "os" and a.asname is None for a in node.names):
            return None
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last = node
    if last is None or last.end_lineno != last.lineno:
        return None   # 여러 줄 import 뒤에는 자동으로 끼우지 않음
    return last.lineno
