"""MCP Hub 에 security 모듈을 등록한다.

허브 DB(DATABASE_URL, 기본은 mcp_hub 설정)에 capability 2개 · 서비스 행 · prod 라이선스를 넣고,
나머지(도구 · provides)는 허브의 manifest 스캔(POST /hub/scan)이 security/__init__.py 에서 채운다.

    DATABASE_URL=sqlite:///...  python scripts/register_hub.py [--hub http://127.0.0.1:8100]
"""
import argparse
import sys
import urllib.request
import uuid
from datetime import datetime, timedelta
from pathlib import Path

HUB_ROOT = Path(r"D:\Vibe_coding\mcp_hub")
SECURITY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HUB_ROOT))

from database import SessionLocal  # noqa: E402
from models import Capability, Environment, License, LicenseStatus, Service, ServiceKind  # noqa: E402

CAPS = {
    "security.scan": ("security", "서비스 저장소 취약점 진단 (SAST · 의존성 CVE · 비밀정보 · 설정/개인정보)"),
    "security.remediation": ("security", "진단 결과 수정 패치 — 승인 후 적용 · 되돌리기"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub", help="허브 API 주소. 주면 등록 후 manifest 스캔까지 실행")
    args = ap.parse_args()
    db = SessionLocal()
    now = datetime.utcnow()
    try:
        for name, (cat, desc) in CAPS.items():
            if not db.query(Capability).filter(Capability.name == name).first():
                db.add(Capability(name=name, category=cat, description=desc))
        if not db.query(Service).filter(Service.id == "security").first():
            db.add(Service(id="security", kind=ServiceKind.MODULE, version="0.1.0",
                           description="전체 서비스 취약점 진단 및 승인 후 수정 조치",
                           source_root=str(SECURITY_ROOT), source_entry="security/__init__.py", scanned_at=now))
        if not db.query(License).filter(License.service_id == "security").first():
            db.add(License(id=str(uuid.uuid4()), service_id="security", environment=Environment.PROD, features=[],
                           status=LicenseStatus.ACTIVE, issued_at=now, expires_at=now + timedelta(days=365),
                           issued_by="security"))
        db.commit()
        print("등록 완료: security")
    finally:
        db.close()
    if args.hub:
        req = urllib.request.Request(f"{args.hub.rstrip('/')}/hub/scan", method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            print(r.read().decode("utf-8"))


if __name__ == "__main__":
    main()
