# Security_AI
AI 모델들로 CVE, 개인정보, 웹 등 취약점 수집 및 MCP 허브 연결 후 다른 서비스 전체 점검 및 딸깍 조치

마지막 업데이트: 2026-09-28 22:31

## 구성
- 진단 4종 (`security/scanners/`)
  - `sast` — 코드 취약점 (Python AST · JS 패턴: eval, 셸 실행, SQL 조립, yaml.load, verify=False, innerHTML 등)
  - `deps` — 의존성 CVE (requirements · pyproject · package.json 을 OSV 에 조회. 패키지명·버전만 전송)
  - `secrets` — 키 · 토큰 · 비밀번호 하드코딩, .env 커밋/미제외
  - `config` — DEBUG, CORS, 쿠키 속성, 로그 비밀값, 고유식별정보 평문 저장 (개인정보보호법 제24조)
- AI (`security/ai/`) — Claude · Gemini · OpenAI 중 키가 있는 모델을 **모두 동시에** 쓰고 결과를 합의로 합친다
  - `intel` — 최신 위협 수집: CISA KEV(실제 악용 중) + NVD 최근 CVE → 서비스 의존성과 대조해 AI 가 해당하는 것만 추림 (패키지명·버전과 공개 CVE 설명만 전송)
  - `review` — AI 코드 검토: 인가 누락 · IDOR · 경로 조작 · SSRF 등 규칙으로 못 잡는 것. 모델이 짚은 줄이 실제와 다르면 버림, 한 모델만 지목하면 심각도 한 단계 낮춤
  - `triage` — 기존 결과를 모델 다수결로 실제/오탐 판정(표시만, 자동 무시 안 함), 자동 수정 없는 항목엔 AI 수정안 작성 → 승인 후 적용
  - 코드를 보내는 review · triage 는 `--allow-code`(API `allow_code=true`) 또는 `SECURITY_AI_SEND_CODE=1` 동의가 있어야 하고, 보내기 전 비밀값을 가린다
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

python -m security ai-status                # 사용 가능한 모델
python -m security intel [--days 14]        # 최신 위협 수집
python -m security review --allow-code [--service EMSv3] [--max-files 15]
python -m security triage --allow-code [--limit 30] [--redo]
```

AI 키 (있는 것만 사용): `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`(또는 `GOOGLE_API_KEY`), `OPENAI_API_KEY`.
모델 바꾸기: `SECURITY_AI_CLAUDE_MODEL` · `SECURITY_AI_GEMINI_MODEL` · `SECURITY_AI_OPENAI_MODEL`, 일부만 쓰기: `SECURITY_AI_PROVIDERS=claude,gemini`.
NVD 수집이 느리면 `NVD_API_KEY` 를 주면 빨라진다.

API: `GET /ai/status`, `POST /ai/intel?days=`, `POST /ai/review?allow_code=true&service=`, `POST /ai/triage?allow_code=true&service=`

진단 대상은 `targets.json` (서비스 id → 저장소 경로). `HUB_URL` 을 주면 허브에 등록된 서비스도 자동으로 대상에 넣고, 심각/높음 결과를 허브 모니터링 이벤트로 보고한다.

허브 등록: `python scripts/register_hub.py --hub http://127.0.0.1:8100`

## 테스트
```
python -m pytest -q
```
