"""python -m security scan|list|show|apply|rollback|dismiss|serve"""
from __future__ import annotations

import argparse
import sys

from . import engine, remediate, store
from .targets import load_targets


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
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, default=8200)
    args = p.parse_args(argv)

    if args.cmd == "serve":
        import uvicorn
        uvicorn.run("security.api:app", host="127.0.0.1", port=args.port)
        return 0
    con = store.connect()
    try:
        if args.cmd == "scan":
            r = engine.run(load_targets(), args.service, args.offline)
            for svc, c in r["services"].items():
                print(f"{svc:14} 심각 {c['critical']:3}  높음 {c['high']:3}  중간 {c['medium']:3}  낮음 {c['low']:3}")
        elif args.cmd == "list":
            for f in store.list_findings(con, service=args.service, category=args.category,
                                         severity=args.severity, status=args.status):
                auto = "자동" if f["fix"] and f["fix"]["automatic"] else "수동"
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
            if f["fix"]:
                print("조치:", f["fix"]["description"])
            print(remediate.diff(con, load_targets(), args.id))
        elif args.cmd == "apply":
            print(remediate.apply(con, load_targets(), args.id, args.by))
        elif args.cmd == "rollback":
            print(remediate.rollback(con, args.id))
        elif args.cmd == "dismiss":
            print(remediate.dismiss(con, args.id, args.reason))
    except remediate.RemediationError as e:
        print("거부:", e)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
