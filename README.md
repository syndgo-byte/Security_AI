# Security_AI
AI 모델들로 CVE, 개인정보, 웹 등 취약점 수집 및 MCP 허브 연결 후 다른 서비스 전체 점검 및 딸깍 조치

마지막 업데이트: 2026-10-03 21:55 (Asia/Seoul)

## 구성
- 진단 6종 (`security/scanners/`)
  - `sast` — 코드 취약점 (Python AST · JS 패턴: eval, 셸 실행, SQL 조립, yaml.load, verify=False, innerHTML 등)
  - `deps` — 의존성 CVE (requirements · pyproject · package.json 을 OSV 에 조회. 패키지명·버전만 전송)
  - `secrets` — 키 · 토큰 · 비밀번호 하드코딩, .env 커밋/미제외
  - `config` — DEBUG, CORS, 쿠키 속성, 로그 비밀값, 고유식별정보 평문 저장 (개인정보보호법 제24조)
  - `hardening` — 실행 권한 · 외부 노출 · 백도어 흔적 (root 실행, privileged, cap_add, 0.0.0.0 바인딩, raw 소켓/BPF)
  - `legal` — 「개인정보의 안전성 확보조치 기준」 기술 항목: 접속기록 보관(제8조①) · 세션 만료(제6조④) · 관리자 추가 인증(제6조②) · 비밀번호 일방향 암호화(제7조①). 정적 분석이라 '없다는 증거'일 뿐이어서 제목에 '확인 필요', 심각도 medium 이하
- AI (`security/ai/`) — Claude · Gemini · OpenAI 중 키가 있는 모델을 **모두 동시에** 쓰고 결과를 합의로 합친다
  - `intel` — 최신 위협 수집: CISA KEV(실제 악용 중) + NVD 최근 CVE → 서비스 의존성과 대조해 AI 가 해당하는 것만 추림 (패키지명·버전과 공개 CVE 설명만 전송)
  - `review` — AI 코드 검토: 인가 누락 · IDOR · 경로 조작 · SSRF 등 규칙으로 못 잡는 것. 모델이 짚은 줄이 실제와 다르면 버림, 한 모델만 지목하면 심각도 한 단계 낮춤
  - `triage` — 기존 결과를 모델 다수결로 실제/오탐 판정(표시만, 자동 무시 안 함), 자동 수정 없는 항목엔 AI 수정안 작성 → 승인 후 적용
  - 코드를 보내는 review · triage 는 `--allow-code`(API `allow_code=true`) 또는 `SECURITY_AI_SEND_CODE=1` 동의가 있어야 하고, 보내기 전 비밀값을 가린다
- `web` — 실행 중인 웹 서비스 **가벼운 점검** (GET 몇 번, 공격 페이로드 없음): 보안 헤더 · 쿠키 속성 · CORS · HTTPS · `.env`/`.git` 노출 · 인증서 만료
- 조치 정책 (`security/policy.py`) — 항목마다 처리 주체를 정한다
  | 구분 | 조건 | 처리 |
  |---|---|---|
  | 넘김 `escalate` | critical, 또는 수정안 없는 high | 사람에게 넘김 (새로 생기면 허브 이벤트로 한 번 보고) |
  | 자동 `auto` | 규칙 기반 수정이 있고 동작을 안 바꾸는 것 (yaml.safe_load, verify 켜기, .gitignore 등) | 모듈이 조치안을 바로 만들어 허브로 |
  | 승인 `approve` | AI 수정안 · 의존성 업그레이드 · 비밀값 이동 · CORS | 허브에서 승인하면 조치안으로 |
  | 직접 `manual` | 수정안 없는 medium 이하 | 안내만 |
- 조치는 **허브가 관리** (`remediate.prepare_patches`) — 모듈은 서비스 코드를 읽기만 하고 조치안(diff)을 만든다: 열림 → 조치안 준비됨(`ready`, `GET /patches`) → 허브가 반영하면 `delivered` → 다음 진단에서 안 나오면 해결로 정리. 코드가 바뀌어 조치안이 안 맞으면 다시 열림. 서비스 로컬 파일 · git 은 건드리지 않는다
  (예외: `SECURITY_AUTO_FIX_MODE=branch` 로 켜면 저장소에 `security/auto-*` 브랜치 커밋)
- 상시 진단 (`security/watch.py`) — 허브에 연결된 서비스는 계속: 코드 30분 · 웹 6시간 · 위협 수집 하루 주기, 코드 진단 뒤 자동 조치
- 수동 승인 조치 (`security/remediate.py`) — 줄 단위 패치(diff)를 보여주고 **승인해야만** 적용. 적용 전 `.backups/` 에 원본 백업, 이후 파일이 안 바뀌었으면 되돌리기 가능
- MCP Hub 연동 — `security/__init__.py` 의 `manifest()` 를 허브가 읽어 등록, 허브 웹 '보안 진단' 탭이 `/security` → 8200 으로 호출

## 커널 하드닝 (host)

호스트 커널을 점검하고, 백업 후 하드닝 → 베이스라인 저장 → 핵심 징후 감시 순서로 운용한다 (리눅스 전용).

```
python -m security kernel audit
python -m security kernel harden [--apply] [--block-userns|--allow-userns]
python -m security kernel rollback
python -m security kernel baseline
python -m security kernel monitor [--once] [--interval 60]
```

- `audit` — 커널 버전 기준 CVE 노출 가능성 · sysctl · 위험 모듈 점검. 배포판 백포트 여부는 별도 확인
- `harden` — 기본은 **dry-run** (변경 diff만 출력). `--apply` 때 설정을 백업하고 sysctl.d · modprobe.d 및 런타임에 적용
- 이미 로드된 모듈은 블랙리스트에 넣지 않는다. 컨테이너 런타임이 감지되면 userns 차단은 기본 제외 (`--block-userns`로 강제 차단, `--allow-userns`로 제외)
- `rollback` — 마지막 백업으로 설정 · 런타임 원복. `baseline` — 조치 후 상태 스냅샷 저장
- `monitor` — 기본 60초마다 설정 drift 복구 · 차단 모듈 로드 감시. 시스템콜 · 권한 상승 탐지는 **auditd 필요**, 없으면 drift 감시만 동작. 이벤트가 있을 때만 JSON 한 줄 출력, `--once`는 한 번 점검하고 결과 출력

API: `GET /kernel/audit`, `POST /kernel/harden?dry_run=true` (`userns=true|false`, 생략 시 자동),
`POST /kernel/rollback`, `GET /kernel/baseline` (저장된 스냅샷, 없으면 404), `POST /kernel/monitor` (한 번 점검 · 알림 저장).
API도 `dry_run=true`가 기본이며 실제 적용은 `dry_run=false`.

## 사용
```
pip install -e .[dev]
python -m security scan [--service EMSv3] [--offline]
python -m security list [--severity high] [--status open]   # --json: 기계용 출력(ops/compliance 가 읽음)
python -m security targets                      # 진단 대상 목록 JSON (code · web)
python -m security show <id>                # 상세 + diff
python -m security apply <id> --by 홍길동    # 승인 후 적용
python -m security rollback <id>
python -m security serve --port 8200        # API (허브 웹이 사용)

python -m security ai-status                # 사용 가능한 모델
python -m security intel [--days 14]        # 최신 위협 수집
python -m security review --allow-code [--service EMSv3] [--max-files 15]
python -m security triage --allow-code [--limit 30] [--redo]

python -m security web [--service EMSv3]    # 웹 가벼운 점검
python -m security auto-fix [--service x]   # 간단한 항목 → 브랜치 커밋
python -m security escalations              # 사람에게 넘긴 항목
python -m security watch [--once]           # 상시 진단
python -m security serve --watch            # API + 상시 진단
```

AI 모델: Claude 는 설치된 Claude Code CLI(claude-opus-5-5, 키 불필요), 그 외 `GEMINI_API_KEY`(또는 `GOOGLE_API_KEY`) · `OPENAI_API_KEY` 가 있으면 같이 쓴다.
모델 바꾸기: `SECURITY_AI_GEMINI_MODEL` · `SECURITY_AI_OPENAI_MODEL`, 일부만 쓰기: `SECURITY_AI_PROVIDERS=claude,gemini`.
정책 · 주기 설정은 `.env.example` 참고.
NVD 수집이 느리면 `NVD_API_KEY` 를 주면 빨라진다.

API: `GET /ai/status`, `POST /ai/intel?days=`, `POST /ai/review?allow_code=true&service=`, `POST /ai/triage?allow_code=true&service=`,
`POST /web/scan`, `POST /auto-fix`(조치안 준비), `GET /patches`, `POST /findings/{id}/approve|cancel|delivered`, `GET /escalations`, `GET /watch`, `GET /findings?action=auto|approve|manual|escalate`

진단 대상은 `targets.json` (서비스 id → 저장소 경로, 또는 `{"root": 경로, "url": "http://127.0.0.1:8000"}` — url 은 목록도 가능, root 없이 url 만 있으면 웹 점검만). `HUB_URL` 을 주면 허브에 등록된 서비스도 자동으로 대상에 넣고, 심각/높음 결과를 허브 모니터링 이벤트로 보고한다.

허브 등록: `python scripts/register_hub.py --hub http://127.0.0.1:8100`

## 테스트
```
python -m pytest -q
```
