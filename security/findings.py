"""진단 결과와 수정 패치 표현."""
from __future__ import annotations

import difflib
import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low")
CATEGORIES = ("sast", "deps", "secrets", "config", "web")


@dataclass
class Edit:
    """한 줄 교체. old 가 현재 파일 내용과 정확히 같을 때만 적용한다 (스캔 이후 파일이 바뀌면 거부)."""
    file: str      # 서비스 루트 기준 상대 경로
    line: int      # 1부터
    old: str       # 줄바꿈 제외한 기존 줄
    new: str       # 교체할 내용 (여러 줄 가능)


@dataclass
class Fix:
    description: str
    edits: list[Edit] = field(default_factory=list)   # 비어 있으면 수동 조치 안내만

    @property
    def automatic(self) -> bool:
        return bool(self.edits)


@dataclass
class Finding:
    service: str
    category: str
    rule: str
    severity: str
    title: str
    file: str
    line: int
    detail: str
    evidence: str = ""
    fix: Fix | None = None

    @property
    def id(self) -> str:
        key = f"{self.service}|{self.rule}|{self.file}|{self.line}|{self.evidence}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        return d


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def render_diff(root: Path, edits: list[Edit]) -> str:
    """edits 를 적용했을 때의 unified diff (파일별)."""
    out = []
    by_file: dict[str, list[Edit]] = {}
    for e in edits:
        by_file.setdefault(e.file, []).append(e)
    for rel, file_edits in by_file.items():
        path = root / rel
        before = read_lines(path) if path.exists() else []
        after = apply_edits(before, file_edits)
        out.extend(difflib.unified_diff(before, after, f"a/{rel}", f"b/{rel}", lineterm=""))
    return "\n".join(out)


def apply_edits(lines: list[str], edits: list[Edit]) -> list[str]:
    """아래쪽 줄부터 교체해 앞쪽 줄 번호가 밀리지 않게 한다. line 0 은 파일 끝에 덧붙이기."""
    result = list(lines)
    for e in sorted(edits, key=lambda x: x.line, reverse=True):
        if e.line == 0:
            result.extend(e.new.splitlines())
            continue
        idx = e.line - 1
        if idx >= len(result) or result[idx] != e.old:
            raise ValueError(f"{e.file}:{e.line} 내용이 진단 이후 바뀌었습니다. 다시 진단하세요.")
        result[idx:idx + 1] = e.new.splitlines()
    return result
