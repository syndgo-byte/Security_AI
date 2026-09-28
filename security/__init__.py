"""security — 내 전체 서비스 취약점 진단 · 수정 조치 모듈 (MCP Hub 공통 모듈).

진단 4종: 코드 취약점(SAST) · 의존성 CVE · 비밀정보 노출 · 설정/개인정보 점검.
수정 조치: 진단마다 줄 단위 패치(diff)를 만들고, 승인해야만 대상 저장소에 반영(백업 · 되돌리기 가능).

허브는 이 파일을 단독으로 불러와 manifest()만 호출하므로, 여기에는 상대 import를 두지 않는다.
"""
from datetime import datetime, timezone
from pathlib import Path

__version__ = "0.1.0"
ROOT = Path(__file__).resolve().parent.parent


def manifest() -> dict:
    return {
        "id": "security",
        "kind": "module",
        "version": __version__,
        "description": "전체 서비스 취약점 진단 (SAST · 의존성 CVE · 비밀정보 · 설정/개인정보) 및 승인 후 수정 조치",
        "provides": ["security.scan", "security.remediation"],
        "requires": [],
        "tools": [
            {"name": "security.scan_services", "description": "등록된 서비스 저장소 전체 또는 하나를 진단",
             "auth_required": "service", "billing_model": "free"},
            {"name": "security.list_findings", "description": "진단 결과 조회 (서비스 · 분류 · 심각도 · 상태 필터)",
             "auth_required": "service", "billing_model": "free"},
            {"name": "security.apply_fix", "description": "승인된 수정 패치를 대상 저장소에 적용 (백업 후)",
             "auth_required": "user", "billing_model": "free"},
            {"name": "security.rollback_fix", "description": "적용한 수정 패치를 백업으로 되돌림",
             "auth_required": "user", "billing_model": "free"},
        ],
        "license": {
            "service_id": "security", "environment": "prod", "status": "active",
            "issued_at": datetime(2026, 9, 28, tzinfo=timezone.utc).isoformat(), "issued_by": "security",
        },
        "source": {"root": str(ROOT), "entry": "security/__init__.py"},
    }
