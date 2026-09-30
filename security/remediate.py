"""승인 후 수정 적용 · 되돌리기. 적용 전 원본을 .backups 에 복사한다."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from . import ROOT
from .findings import apply_edits, read_lines, render_diff
from .store import get, now, row_fix

BACKUPS = ROOT / ".backups"


class RemediationError(Exception):
    pass


def _hash(root: Path, files: list[str]) -> str:
    h = hashlib.sha256()
    for rel in sorted(files):
        p = root / rel
        h.update(rel.encode())
        h.update(p.read_bytes() if p.exists() else b"\0missing")
    return h.hexdigest()


def _newline(path: Path) -> str:
    return "\r\n" if path.exists() and b"\r\n" in path.read_bytes()[:4096] else "\n"


def write_edits(base: Path, edits) -> list[str]:
    """base 아래 파일에 수정을 쓴다. 줄이 안 맞으면 ValueError (그 전에 쓴 파일은 호출한 쪽이 정리)."""
    files = sorted({e.file for e in edits})
    for rel in files:
        path = base / rel
        before = read_lines(path) if path.exists() else []
        lines = apply_edits(before, [e for e in edits if e.file == rel])
        nl = _newline(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(nl.join(lines) + nl)
    return files


def _verify_key(root: Path, row) -> str:
    """검증한 수정안 + 대상 파일 내용. 검증 뒤 둘 중 하나라도 바뀌면 다시 검증해야 한다."""
    fix = row_fix(row)
    return hashlib.sha256((json.dumps([e.__dict__ for e in fix.edits], ensure_ascii=False)
                           + _hash(root, [e.file for e in fix.edits])).encode()).hexdigest()


def require_verify() -> bool:
    import os
    return os.environ.get("SECURITY_REQUIRE_VERIFY", "1") != "0"


def start_verify(con, targets: dict[str, Path], fid: str) -> tuple[Path, list]:
    """검증을 시작할 수 있는지 확인하고 상태를 running 으로. 실제 검증은 run_verify (오래 걸려 백그라운드)."""
    row = get(con, fid)
    if not row or row["status"] not in ("open", "ready"):
        raise RemediationError("열림 · 조치안 준비됨 상태만 검증할 수 있습니다.")
    fix = row_fix(row)
    if not fix or not fix.automatic:
        raise RemediationError("수정안이 없는 항목입니다.")
    root = targets.get(row["service"])
    if not root:
        raise RemediationError(f"대상 경로를 모릅니다: {row['service']}")
    if row["verify"] and json.loads(row["verify"]).get("state") == "running":
        raise RemediationError("이미 검증 중입니다.")
    con.execute("update findings set verify=? where id=?", (json.dumps({"state": "running", "at": now()}), fid))
    con.commit()
    return root, fix.edits


def run_verify(con, root: Path, fid: str, edits) -> dict:
    from . import alerts, verify
    try:
        result = verify.run(root, edits)
    except Exception as e:   # 검증기 자체 오류도 결과로 남겨 running 에 갇히지 않게
        result = {"ok": False, "state": "error", "at": now(), "steps": [{"name": "검증", "ok": False, "seconds": 0,
                                                                          "note": "검증 도중 오류", "log": repr(e)}]}
    row = get(con, fid)
    if not row:
        return result
    result["key"] = _verify_key(root, row)
    con.execute("update findings set verify=? where id=?", (json.dumps(result, ensure_ascii=False), fid))
    con.commit()
    failed = [s for s in result["steps"] if not s["ok"]]
    if failed:
        alerts.emit(con, row["service"], "verify_failed", "medium", f"검증 실패: {row['title']}",
                    "; ".join(f"{s['name']} {s['note']}".strip() for s in failed), fid)
    else:
        alerts.emit(con, row["service"], "verify_passed", "low", f"검증 통과: {row['title']}",
                    " · ".join(f"{s['name']} {s['note']}".strip() for s in result["steps"]), fid)
    return result


def diff(con, targets: dict[str, Path], fid: str) -> str:
    row = get(con, fid)
    fix = row_fix(row) if row else None
    if not fix or not fix.automatic or row["service"] not in targets:
        return ""
    try:
        return render_diff(targets[row["service"]], fix.edits)
    except ValueError as e:
        return f"# {e}"


def apply(con, targets: dict[str, Path], fid: str, approved_by: str) -> dict:
    row = get(con, fid)
    if not row:
        raise RemediationError("진단 항목이 없습니다.")
    if row["status"] not in ("open", "ready"):
        raise RemediationError(f"이미 처리된 항목입니다 ({row['status']}).")
    if not approved_by.strip():
        raise RemediationError("승인자 이름이 필요합니다.")
    fix = row_fix(row)
    if not fix or not fix.automatic:
        raise RemediationError("자동 수정이 없는 항목입니다. 안내에 따라 직접 조치하세요.")
    root = targets.get(row["service"])
    if not root:
        raise RemediationError(f"대상 경로를 모릅니다: {row['service']}")
    if require_verify():
        v = json.loads(row["verify"]) if row["verify"] else {}
        if v.get("state") != "passed":
            raise RemediationError("동작 검증을 통과한 조치안만 적용할 수 있습니다. 먼저 '동작 검증'을 돌리세요.")
        if v.get("key") != _verify_key(root, row):
            raise RemediationError("검증한 뒤 수정안이나 대상 파일이 바뀌었습니다. 다시 검증하세요.")

    files = sorted({e.file for e in fix.edits})
    new_content = {}
    for rel in files:   # 먼저 전부 계산해 하나라도 어긋나면 아무 파일도 건드리지 않는다
        path = root / rel
        before = read_lines(path) if path.exists() else []
        try:
            new_content[rel] = apply_edits(before, [e for e in fix.edits if e.file == rel])
        except ValueError as e:
            raise RemediationError(str(e)) from e

    backup = BACKUPS / f"{fid}-{datetime.now():%Y%m%d-%H%M%S}"
    manifest = {}
    for rel in files:
        src = root / rel
        manifest[rel] = src.exists()
        if src.exists():
            (backup / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, backup / rel)
    backup.mkdir(parents=True, exist_ok=True)
    (backup / "_files.json").write_text(json.dumps({"root": str(root), "files": manifest}, ensure_ascii=False),
                                        encoding="utf-8")

    for rel, lines in new_content.items():
        path = root / rel
        nl = _newline(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(nl.join(lines) + nl)

    applied_hash = _hash(root, files)
    con.execute("update findings set status='applied', approved_by=?, applied_at=?, backup_dir=?, applied_hash=?"
                " where id=?", (approved_by, now(), str(backup), applied_hash, fid))
    con.commit()
    from . import alerts
    alerts.emit(con, row["service"], "applied", "low", f"조치 적용: {row['title']}",
                f"{fix.description} · 승인 {approved_by} · 파일 {', '.join(files)} · 백업 {backup}", fid)
    return {"id": fid, "status": "applied", "files": files, "backup_dir": str(backup)}


def rollback(con, fid: str) -> dict:
    row = get(con, fid)
    if not row or row["status"] != "applied":
        raise RemediationError("적용된 항목만 되돌릴 수 있습니다.")
    backup = Path(row["backup_dir"])
    meta = json.loads((backup / "_files.json").read_text(encoding="utf-8"))
    root = Path(meta["root"])
    if _hash(root, list(meta["files"])) != row["applied_hash"]:
        raise RemediationError("적용 이후 파일이 또 바뀌어 자동으로 되돌릴 수 없습니다. 백업을 보고 직접 비교하세요: "
                               + str(backup))
    for rel, existed in meta["files"].items():
        if existed:
            shutil.copy2(backup / rel, root / rel)
        else:
            (root / rel).unlink(missing_ok=True)
    con.execute("update findings set status='rolled_back', verify=null where id=?", (fid,))
    con.commit()
    from . import alerts
    alerts.emit(con, row["service"], "rolled_back", "medium", f"조치 되돌림: {row['title']}",
                ", ".join(meta["files"]), fid)
    return {"id": fid, "status": "rolled_back", "files": list(meta["files"])}


def prepare_patches(con, targets: dict[str, Path], ids: list[str] | None = None) -> dict:
    """정책상 auto 인 항목의 조치안(diff)을 만들어 허브가 가져가게 둔다. 서비스 파일 · git 은 읽기만 한다.

    open → ready(조치안 준비됨). 이미 ready 인 것도 다시 계산해, 코드가 바뀌어 안 맞으면 open 으로 되돌린다.
    """
    from .policy import decide
    rows = [r for r in con.execute("select * from findings where status in ('open', 'ready')")
            if (ids is None or r["id"] in ids) and r["service"] in targets and decide(r) == "auto"]
    ready, stale = [], []
    for r in rows:
        try:
            patch = render_diff(targets[r["service"]], row_fix(r).edits)
        except (ValueError, OSError):
            patch = ""
        if patch:
            con.execute("update findings set status='ready', patch=? where id=?", (patch, r["id"]))
            ready.append(r["id"])
        elif r["status"] == "ready":
            con.execute("update findings set status='open', patch=null where id=?", (r["id"],))
            stale.append(r["id"])
    con.commit()
    return {"ready": ready, "reopened": stale}


def approve(con, targets: dict[str, Path], fid: str, approved_by: str) -> dict:
    """사람이 승인한 수정안을 조치안(ready)으로 만든다 — 승인 대기 · 넘김 항목용. 서비스 파일은 안 건드린다."""
    row = get(con, fid)
    if not row or row["status"] != "open":
        raise RemediationError("열린 항목만 승인할 수 있습니다.")
    if not approved_by.strip():
        raise RemediationError("승인자 이름이 필요합니다.")
    fix = row_fix(row)
    if not fix or not fix.automatic:
        raise RemediationError("수정안이 없는 항목입니다. 안내에 따라 직접 조치하세요.")
    if row["service"] not in targets:
        raise RemediationError(f"대상 경로를 모릅니다: {row['service']}")
    try:
        patch = render_diff(targets[row["service"]], fix.edits)
    except ValueError as e:
        raise RemediationError(str(e)) from e
    con.execute("update findings set status='ready', patch=?, approved_by=? where id=?", (patch, approved_by, fid))
    con.commit()
    return {"id": fid, "status": "ready"}


def cancel(con, fid: str) -> dict:
    """조치안을 거둬들여 다시 열림으로."""
    row = get(con, fid)
    if not row or row["status"] != "ready":
        raise RemediationError("조치안 준비됨 상태만 취소할 수 있습니다.")
    con.execute("update findings set status='open', patch=null, approved_by=null where id=?", (fid,))
    con.commit()
    return {"id": fid, "status": "open"}


def mark_delivered(con, fid: str, by: str) -> dict:
    """허브가 조치안을 서비스에 반영했다고 알려줄 때. 다음 진단에서 안 나오면 해결로 정리된다."""
    row = get(con, fid)
    if not row or row["status"] != "ready":
        raise RemediationError("조치안 준비됨 상태만 반영 처리할 수 있습니다.")
    if not by.strip():
        raise RemediationError("반영한 사람(또는 허브 작업 id)이 필요합니다.")
    con.execute("update findings set status='delivered', approved_by=?, applied_at=? where id=?", (by, now(), fid))
    con.commit()
    return {"id": fid, "status": "delivered"}


def auto_remediate(con, targets: dict[str, Path]) -> dict:
    """상시 진단용 자동 조치. 기본은 허브 관리(조치안만 준비), SECURITY_AUTO_FIX_MODE=branch 면 저장소 브랜치 커밋."""
    import os
    if os.environ.get("SECURITY_AUTO_FIX_MODE", "patch") == "branch":
        return {"mode": "branch", **auto_fix(con, targets)}
    return {"mode": "patch", **prepare_patches(con, targets)}


WORKTREES = ROOT / ".worktrees"


def _git(cwd: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise RemediationError(f"git {args[0]}: {(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout.strip()


def auto_fix(con, targets: dict[str, Path], ids: list[str] | None = None) -> dict:
    """정책상 auto 인 항목을 서비스 저장소의 새 브랜치에 커밋한다.

    작업 폴더 · 현재 브랜치는 건드리지 않는다: git worktree 로 따로 꺼내 고친 뒤 worktree 는 지우고 브랜치만 남긴다.
    병합은 사람이 한다. git 저장소가 아니면 건너뛴다.
    """
    from .policy import decide
    rows = [r for r in con.execute("select * from findings where status='open'")
            if (ids is None or r["id"] in ids) and decide(r) == "auto" and r["service"] in targets]
    by_service: dict[str, list] = {}
    for r in rows:
        by_service.setdefault(r["service"], []).append(r)

    result = {"branches": {}, "skipped": []}
    for service, items in by_service.items():
        root = targets[service].resolve()
        try:
            top = Path(_git(root, "rev-parse", "--show-toplevel")).resolve()
        except (RemediationError, OSError):
            result["skipped"] += [f"{service}: git 저장소가 아니라 자동 조치 안 함"]
            continue
        sub = root.relative_to(top)
        branch = f"security/auto-{service}-{datetime.now():%Y%m%d-%H%M%S}"
        wt = WORKTREES / f"{service}-{datetime.now():%Y%m%d-%H%M%S}"
        wt.parent.mkdir(parents=True, exist_ok=True)
        _git(top, "worktree", "add", "-q", "-b", branch, str(wt), "HEAD")
        done = []
        try:
            for r in items:
                fix = row_fix(r)
                try:
                    changed = [str(sub / rel) for rel in write_edits(wt / sub, fix.edits)]
                except ValueError:   # 커밋 안 된 변경 위에서 진단된 줄 → HEAD 와 달라 건너뜀
                    _git(wt, "checkout", "-q", "--", ".")
                    result["skipped"].append(f"{service} {r['id']}: 커밋된 코드와 달라 건너뜀 ({r['file']}:{r['line']})")
                    continue
                _git(wt, "add", "--", *changed)
                _git(wt, "-c", "user.name=MCP Hub Security", "-c", "user.email=security@mcp-hub.local",
                     "commit", "-q", "--no-verify", "-m", f"fix(security): {r['rule']} {r['file']}:{r['line']}\n\n"
                     f"{r['title']}\n{fix.description}\n\nfinding: {r['id']}")
                done.append(r["id"])
        finally:
            _git(top, "worktree", "remove", "--force", str(wt))
        if not done:
            _git(top, "branch", "-q", "-D", branch)
            continue
        con.executemany("update findings set status='branch', approved_by='auto', applied_at=?, backup_dir=? where id=?",
                        [(now(), branch, i) for i in done])
        con.commit()
        result["branches"][service] = {"branch": branch, "repo": str(top), "fixed": done}
    return result


def dismiss(con, fid: str, reason: str = "") -> dict:
    row = get(con, fid)
    if not row:
        raise RemediationError("진단 항목이 없습니다.")
    con.execute("update findings set status='dismissed', approved_by=? where id=?", (reason or None, fid))
    con.commit()
    return {"id": fid, "status": "dismissed"}
