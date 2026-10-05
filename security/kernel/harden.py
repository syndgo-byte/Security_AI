"""Back up, harden and roll back host settings (dry-run by default)."""
from __future__ import annotations

import difflib
import json
from datetime import datetime

from .baseline import baseline
from .host import BLACKLIST, MODPROBE_CONF, SYSCTL_CONF, TARGETS, USERNS_KEY, Host, _now, _unsupported


def _keys(h: Host, userns: bool | None) -> dict[str, str]:
    """적용할 sysctl. 커널에 없는 키는 빼고, 컨테이너가 돌면 userns 차단은 기본 제외."""
    block_userns = (not h.containers()) if userns is None else userns
    return {k: v[0] for k, v in TARGETS.items()
            if h.sysctl(k) is not None and (k != USERNS_KEY or block_userns)}


def _plan(h: Host, userns: bool | None) -> dict:
    keys = _keys(h, userns)
    loaded = set(h.modules())
    mods = [m for m in BLACKLIST if m not in loaded]
    sysctl_txt = "# kernel hardening (security ops)\n" + "".join(f"{k} = {v}\n" for k, v in keys.items())
    mod_txt = "# kernel hardening (security ops)\n" + "".join(f"blacklist {m}\ninstall {m} /bin/false\n" for m in mods)
    return {"sysctl": keys, "modules": mods, "skipped_loaded": sorted(loaded & set(BLACKLIST)),
            "files": {SYSCTL_CONF: sysctl_txt, MODPROBE_CONF: mod_txt}}


def _diff(h: Host, files: dict[str, str]) -> str:
    out = []
    for rel, new in files.items():
        f = h.p(rel)
        old = f.read_text().splitlines() if f.exists() else []
        out.extend(difflib.unified_diff(old, new.splitlines(), f"a/{rel}", f"b/{rel}", lineterm=""))
    return "\n".join(out)


def harden(h: Host, dry_run: bool = True, userns: bool | None = None) -> dict:
    if not h.supported:
        return _unsupported()
    plan = _plan(h, userns)
    runtime = {k: h.sysctl(k) for k in plan["sysctl"] if h.sysctl(k) != plan["sysctl"][k]}
    result = {"supported": True, "dry_run": dry_run, "sysctl": plan["sysctl"], "runtime_changes": runtime,
              "modules": plan["modules"], "skipped_loaded": plan["skipped_loaded"], "diff": _diff(h, plan["files"])}
    if dry_run:
        return result
    bdir = h.state / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    bdir.mkdir(parents=True)
    saved = {}
    for rel, content in plan["files"].items():
        f = h.p(rel)
        saved[rel] = f.read_text() if f.exists() else None
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
    (bdir / "backup.json").write_text(json.dumps({"at": _now(), "files": saved, "runtime": runtime}, ensure_ascii=False, indent=1))
    result["failed"] = [k for k, v in plan["sysctl"].items() if k in runtime and not h.set_sysctl(k, v)]
    result["backup"] = str(bdir)
    result["baseline"] = baseline(h)
    return result


def rollback(h: Host) -> dict:
    if not h.supported:
        return _unsupported()
    dirs = sorted(d for d in h.state.glob("*") if (d / "backup.json").exists()) if h.state.is_dir() else []
    if not dirs:
        return {"supported": True, "ok": False, "reason": "백업 없음"}
    data = json.loads((dirs[-1] / "backup.json").read_text())
    for rel, content in data["files"].items():
        f = h.p(rel)
        if content is None:
            f.unlink(missing_ok=True)
        else:
            f.write_text(content)
    restored = {k: v for k, v in data["runtime"].items() if v is not None and h.set_sysctl(k, v)}
    (h.state / "baseline.json").unlink(missing_ok=True)
    (dirs[-1] / "backup.json").rename(dirs[-1] / "backup.restored.json")
    return {"supported": True, "ok": True, "backup": str(dirs[-1]), "runtime_restored": restored}
