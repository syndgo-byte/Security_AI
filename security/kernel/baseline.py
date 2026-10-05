"""Capture and load the state after hardening."""
from __future__ import annotations

import hashlib
import json

from .host import BLACKLIST, SYSCTL_CONF, Host, _now


def baseline(h: Host) -> dict:
    conf = h.p(SYSCTL_CONF)
    keys = {}
    if conf.exists():
        for ln in conf.read_text().splitlines():
            if "=" in ln and not ln.lstrip().startswith("#"):
                k, v = ln.split("=", 1)
                keys[k.strip()] = v.strip()
    snap = {"at": _now(), "kernel": h.kernel(), "sysctl": keys,
            "sysctl_sha256": hashlib.sha256(json.dumps(keys, sort_keys=True).encode()).hexdigest(),
            "blacklist": sorted(h.blacklisted() & set(BLACKLIST)), "modules": sorted(h.modules()), "bpf": h.bpf_programs()}
    h.state.mkdir(parents=True, exist_ok=True)
    (h.state / "baseline.json").write_text(json.dumps(snap, ensure_ascii=False, indent=1))
    return snap


def load_baseline(h: Host) -> dict | None:
    f = h.state / "baseline.json"
    return json.loads(f.read_text()) if f.exists() else None
