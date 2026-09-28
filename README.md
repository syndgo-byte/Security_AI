# Security_AI
AI 모델들로 CVE, 개인정보, 웹 등 취약점 수집 및 MCP 허브 연결 후 다른 서비스 전체 점검 및 딸깍 조치

마지막 업데이트: 2026-09-28 21:44

## 구성
- 진단 4종 (`security/scanners/`)
  - `sast` — 코드 취약점 (Python AST · JS 패턴: eval, 셸 실행, SQL 조립, yaml.load, verify=False, innerHTML 등)
  - `deps` — 의존성 CVE (requirements · pyproject · package.json 을 OSV 에 조회. 패키지명·버전만 전송)
  - `secrets` — 키 · 토큰 · 비밀번호 하드코딩, .env 커밋/미제외
  - `config` — DEBUG, CORS, 쿠키 속성, 로그 비밀값, 고유식별정보 평문 저장 (개인정보보호법 제24조)
- 수정 조치 (`security/remediate.py`) — 줄 단위 패치(diff)를 보여주고 **승인해야만** 적용. 적용 전 `.backups/` 에 원본 백업, 이후 파일이 안 바뀌었으면 되돌리기 가능
- MCP Hub 연동 — `security/__init__.py` 의 `manifest()` 를 허브가 읽어 등록, 허브 웹 '보안 진단' 탭이 `/security` → 8200 으로 호출

## 사용
```
pip install -e .[dev]
python -m security scan [--service EMSv3] [--offline]
python -m security list [--severity high] [--status open]
python -m security show <id>                # 상세 + diff
python -m security apply <id> --by 홍길동    # 승인 후 적용
python -m security rollback <id>
python -m security serve --port 8200        # API (허브 웹이 사용)
```

진단 대상은 `targets.json` (서비스 id → 저장소 경로). `HUB_URL` 을 주면 허브에 등록된 서비스도 자동으로 대상에 넣고, 심각/높음 결과를 허브 모니터링 이벤트로 보고한다.

허브 등록: `python scripts/register_hub.py --hub http://127.0.0.1:8100`

## 테스트
```
python -m pytest -q
```
