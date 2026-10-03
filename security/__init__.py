"""security — 내 전체 서비스 취약점 진단 · 수정 조치 모듈 (MCP Hub 공통 모듈).

진단 4종: 코드 취약점(SAST) · 의존성 CVE · 비밀정보 노출 · 설정/개인정보 점검.
AI (security/ai): 최신 위협 수집 · 코드 검토 · 오탐 판정/수정안 — Claude · Gemini · OpenAI 중 키가 있는 모델 모두 사용.
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
        "kind": "ops",  # 관리 서비스: 모든 서비스를 점검 (허브 위, 3D 관제판에서는 달 · 태양)
        "version": __version__,
        "description": "전체 서비스 취약점 진단 (SAST · 의존성 CVE · 비밀정보 · 설정/개인정보 · AI 위협 수집/검토) 및 승인 후 수정 조치",
        "provides": ["security.scan", "security.remediation", "security.watch", "security.kernel"],
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
            {"name": "security.ai_intel", "description": "최신 위협 수집 (CISA KEV · NVD) 후 AI 가 서비스 의존성과 대조",
             "auth_required": "service", "billing_model": "free"},
            {"name": "security.ai_review", "description": "여러 AI 모델로 코드 검토 (코드 전송 동의 필요)",
             "auth_required": "user", "billing_model": "free"},
            {"name": "security.ai_triage", "description": "AI 다수결 오탐 판정 · 수정안 작성 (승인 후 적용)",
             "auth_required": "user", "billing_model": "free"},
            {"name": "security.web_scan", "description": "실행 중인 웹 서비스 가벼운 점검 (헤더 · 쿠키 · CORS · HTTPS · 노출 경로 · 인증서)",
             "auth_required": "service", "billing_model": "free"},
            {"name": "security.auto_fix", "description": "간단한 항목 자동 조치 (서비스 저장소 새 브랜치에 커밋, 병합은 사람)",
             "auth_required": "service", "billing_model": "free"},
            {"name": "security.escalations", "description": "사람에게 넘긴 항목 (critical · 수정안 없는 high)",
             "auth_required": "service", "billing_model": "free"},
            {"name": "security.kernel_audit", "description": "호스트 커널 하드닝 점검 (CVE 노출 · sysctl · 위험 모듈)",
             "auth_required": "service", "billing_model": "free"},
            {"name": "security.kernel_harden", "description": "커널 하드닝 적용 (백업 · dry-run 기본)",
             "auth_required": "user", "billing_model": "free"},
            {"name": "security.kernel_rollback", "description": "커널 하드닝 원복",
             "auth_required": "user", "billing_model": "free"},
        ],
        "license": {
            "service_id": "security", "environment": "prod", "status": "active",
            "issued_at": datetime(2026, 9, 28, tzinfo=timezone.utc).isoformat(), "issued_by": "security",
        },
        "source": {"root": str(ROOT), "entry": "security/__init__.py"},
    }
