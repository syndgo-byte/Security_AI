"""진단 대상 — targets.json, 그리고 선택적으로 MCP Hub 에 등록된 서비스.

targets.json 값은 저장소 경로 문자열, 또는 {"root": 경로, "url": 웹 주소(들)}.
root 없이 url 만 있으면 코드 진단 없이 웹 점검만 한다.
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

from . import ROOT

TARGETS_FILE = ROOT / "targets.json"


def _entries() -> dict[str, dict]:
    out: dict[str, dict] = {}
    if TARGETS_FILE.exists():
        for sid, v in json.loads(TARGETS_FILE.read_text(encoding="utf-8")).items():
            out[sid] = {"root": v} if isinstance(v, str) else dict(v)
    return out


def _hub_entries(known: dict[str, dict]) -> dict[str, dict]:
    """허브 그래프의 서비스 manifest 에서 source.root · url 을 읽는다."""
    hub = os.environ.get("HUB_URL")
    if not hub:
        return {}
    out = {}
    try:
        with urllib.request.urlopen(f"{hub.rstrip('/')}/hub/graph", timeout=5) as r:
            ids = [n["id"] for n in json.load(r)["nodes"]]
        for sid in ids:
            if sid in known:
                continue
            with urllib.request.urlopen(f"{hub.rstrip('/')}/hub/manifest/{sid}", timeout=5) as r:
                m = json.load(r)
            src = m.get("source") or {}
            e = {"root": src.get("root"), "url": m.get("url") or src.get("url")}
            if e["root"] or e["url"]:
                out[sid] = e
    except (OSError, ValueError, KeyError):
        pass
    return out


def _all(from_hub: bool) -> dict[str, dict]:
    entries = _entries()
    if from_hub:
        entries.update(_hub_entries(entries))
    return entries


def load_targets(from_hub: bool = True) -> dict[str, Path]:
    """코드 진단 대상: 서비스 id → 저장소 경로."""
    out = {sid: Path(e["root"]) for sid, e in _all(from_hub).items() if e.get("root")}
    return {sid: p for sid, p in out.items() if p.is_dir() and p.resolve() != ROOT.resolve()}


def load_sites(from_hub: bool = True) -> dict[str, list[str]]:
    """웹 점검 대상: 서비스 id → 주소 목록."""
    out = {}
    for sid, e in _all(from_hub).items():
        urls = e.get("url") or []
        urls = [urls] if isinstance(urls, str) else list(urls)
        if urls:
            out[sid] = urls
    return out
