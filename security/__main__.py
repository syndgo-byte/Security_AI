"""python -m security scan|list|show|apply|rollback|dismiss|serve"""
from __future__ import annotations

import argparse
import sys

from . import engine, remediate, store
from .targets import load_sites, load_targets


ACTION_LABEL = {"auto": "자동조치", "approve": "승인대기", "manual": "직접조치", "escalate": "넘김"}


def main(argv=None) -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="security", description="서비스 취약점 진단 · 승인 후 수정")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="진단 실행")
    s.add_argument("--service")
    s.add_argument("--offline", action="store_true", help="OSV 조회 안 함 (패키지명·버전 외부 전송 없음)")
    ls = sub.add_parser("list", help="진단 결과 목록")
    for k in ("service", "category", "severity", "status"):
        ls.add_argument(f"--{k}")
    sub.add_parser("show").add_argument("id")
    a = sub.add_parser("apply", help="승인 후 적용")
    a.add_argument("id")
    a.add_argument("--by", required=True, help="승인자")
    sub.add_parser("rollback").add_argument("id")
    d = sub.add_parser("dismiss")
    d.add_argument("id")
    d.add_argument("--reason", default="")
    sub.add_parser("ai-status", help="사용 가능한 AI 모델")
    it = sub.add_parser("intel", help="최신 위협 수집 (CISA KEV · NVD → AI 대조)")
    it.add_argument("--service")
    it.add_argument("--days", type=int, default=14)
    rv = sub.add_parser("review", help="AI 코드 검토 (코드 일부 외부 전송)")
    rv.add_argument("--service")
    rv.add_argument("--allow-code", action="store_true", help="코드 전송 동의 (비밀값은 가린 뒤 전송)")
    rv.add_argument("--max-files", type=int, default=15)
    tr = sub.add_parser("triage", help="AI 오탐 판정 · 수정안 작성")
    tr.add_argument("--service")
    tr.add_argument("--allow-code", action="store_true")
    tr.add_argument("--limit", type=int, default=30)
    tr.add_argument("--redo", action="store_true", help="이미 판정한 항목도 다시")
    sub.add_parser("web", help="웹 가벼운 점검 (헤더 · 쿠키 · CORS · HTTPS · 노출 경로 · 인증서)").add_argument("--service")
    sub.add_parser("auto-fix", help="간단한 항목을 서비스 저장소 새 브랜치에 커밋").add_argument("--service")
    sub.add_parser("escalations", help="사람에게 넘긴 항목").add_argument("--service")
    wa = sub.add_parser("watch", help="상시 진단 (코드 30분 · 웹 6시간 · 위협 수집 하루)")
    wa.add_argument("--once", action="store_true", help="모든 작업을 한 번만 돌리고 끝")
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, default=8200)
    sv.add_argument("--watch", action="store_true", help="상시 진단도 같이 실행")
    args = p.parse_args(argv)

    if args.cmd == "serve":
        import os
        import uvicorn
        if args.watch:
            os.environ["SECURITY_WATCH"] = "1"
        uvicorn.run("security.api:app", host="127.0.0.1", port=args.port)
        return 0
    if args.cmd == "watch":
        from .watch import Watcher
        w = Watcher()

        def show(ran):
            for job, r in ran.items():
                fixed = sum(len(b["fixed"]) for b in r.get("auto_fix", {}).get("branches", {}).values())
                print(f"[{w.status[job]['at']}] {job}: 서비스 {len(r.get('services', {}))}"
                      + (f" · 자동 조치 {fixed}건" if fixed else "") + "".join(f"\n  오류: {e}" for e in r.get("errors", [])))
        if args.once:
            show(w.tick())
            return 0
        try:
            w.loop(show)
        except KeyboardInterrupt:
            pass
        return 0
    from .ai import providers, triage
    from .ai.common import ConsentError
    con = store.connect()
    try:
        if args.cmd in ("scan", "intel", "review", "web"):
            if args.cmd == "scan":
                r = engine.run(load_targets(), args.service, args.offline)
            elif args.cmd == "web":
                r = engine.run_web(load_sites(), args.service)
            elif args.cmd == "intel":
                r = engine.run_intel(load_targets(), args.service, args.days)
            else:
                r = engine.run_review(load_targets(), args.service, args.allow_code, args.max_files)
            for svc, c in r["services"].items():
                print(f"{svc:14} 심각 {c['critical']:3}  높음 {c['high']:3}  중간 {c['medium']:3}  낮음 {c['low']:3}")
            for e in r.get("errors", []):
                print("  오류:", e)
        elif args.cmd == "auto-fix":
            t = {k: v for k, v in load_targets().items() if not args.service or k == args.service}
            r = remediate.auto_fix(con, t)
            for svc, b in r["branches"].items():
                print(f"{svc:14} {len(b['fixed'])}건 → 브랜치 {b['branch']} ({b['repo']}) — 확인 후 병합하세요")
            for s in r["skipped"]:
                print("  건너뜀:", s)
            if not r["branches"] and not r["skipped"]:
                print("자동 조치할 항목 없음")
        elif args.cmd == "escalations":
            for f in store.list_findings(con, service=args.service, status="open", action="escalate"):
                print(f"{f['id']}  {f['severity']:8} {f['service']:12} {f['category']:7} {f['title']}  {f['file']}:{f['line']}")
        elif args.cmd == "ai-status":
            for name, s in providers.status().items():
                print(f"{name:7} {s['state']:8} {s['model']}")
        elif args.cmd == "triage":
            r = triage.run(con, load_targets(), args.service, args.allow_code, args.limit, args.redo)
            print(f"판정 {r['checked']}건: 실제 {r['true_positive']} · 오탐 {r['false_positive']} · 불확실 {r['uncertain']}"
                  f" · AI 수정안 {r['patched']}")
            for e in r["errors"]:
                print("  오류:", e)
        elif args.cmd == "list":
            for f in store.list_findings(con, service=args.service, category=args.category,
                                         severity=args.severity, status=args.status):
                auto = ("AI" if f["fix"]["by_ai"] else "자동") if f["fix"] and f["fix"]["automatic"] else "수동"
                if f.get("ai_verdict") == "false_positive":
                    auto += "·오탐?"
                if f["action"]:
                    auto += "·" + ACTION_LABEL[f["action"]]
                print(f"{f['id']}  {f['severity']:8} {f['status']:11} {f['service']:12} {f['category']:7} "
                      f"[{auto}] {f['title']}  {f['file']}:{f['line']}")
        elif args.cmd == "show":
            row = store.get(con, args.id)
            if not row:
                print("없음")
                return 1
            f = store.to_dict(row)
            print(f"{f['title']} ({f['severity']}, {f['rule']})\n{f['service']} {f['file']}:{f['line']}\n"
                  f"{f['evidence']}\n\n{f['detail']}\n")
            if f.get("ai_verdict"):
                print(f"AI 판정: {f['ai_verdict']}\n{f['ai_note']}\n")
            if f["fix"]:
                print("조치:", f["fix"]["description"])
            print(remediate.diff(con, load_targets(), args.id))
        elif args.cmd == "apply":
            print(remediate.apply(con, load_targets(), args.id, args.by))
        elif args.cmd == "rollback":
            print(remediate.rollback(con, args.id))
        elif args.cmd == "dismiss":
            print(remediate.dismiss(con, args.id, args.reason))
    except (remediate.RemediationError, ConsentError, providers.AIError) as e:
        print("거부:", e)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
