"""AI 분석 — 여러 모델(Claude · Gemini · OpenAI)로 위협 수집 · 코드 검토 · 오탐 판정/수정안.

키가 있는 모델만 쓴다 (ANTHROPIC_API_KEY · GEMINI_API_KEY 또는 GOOGLE_API_KEY · OPENAI_API_KEY).
코드를 보내는 기능(review · triage)은 allow_code=True 또는 SECURITY_AI_SEND_CODE=1 일 때만 동작하며,
보내기 전에 비밀값을 가린다.
"""
