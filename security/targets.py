"""진단 대상 저장소 목록 — targets.json, 그리고 선택적으로 MCP Hub 등록 정보."""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

from . import ROOT

TARGETS_FILE = ROOT / "targets.json"


def load_targets(from_hub: bool = True) -> dict[str, Path]:
    targets: dict[str, Path] = {}
    if TARGETS_FILE.exists():
        for sid, root in json.loads(TARGETS_FILE.read_text(encoding="utf-8")).items():
            targets[sid] = Path(root)
    hub = os.environ.get("HUB_URL")
    if from_hub and hub:
        try:
            with urllib.request.urlopen(f"{hub.rstrip('/')}/hub/graph", timeout=5) as r:
                ids = [n["id"] for n in json.load(r)["nodes"]]
            for sid in ids:
                if sid in targets:
                    continue
                with urllib.request.urlopen(f"{hub.rstrip('/')}/hub/manifest/{sid}", timeout=5) as r:
                    root = (json.load(r).get("source") or {}).get("root")
                if root:
                    targets[sid] = Path(root)
        except (OSError, ValueError, KeyError):
            pass
    return {sid: p for sid, p in targets.items() if p.is_dir() and p.resolve() != ROOT.resolve()}
