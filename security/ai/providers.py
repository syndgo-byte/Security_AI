"""모델 공통 호출. 표준 라이브러리(urllib)만 쓰고, 응답은 JSON 객체로 받는다."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

TIMEOUT = 120


@dataclass
class Provider:
    name: str
    key_envs: tuple[str, ...]
    model_env: str
    default_model: str

    @property
    def key(self) -> str | None:
        return next((os.environ[k] for k in self.key_envs if os.environ.get(k)), None)

    @property
    def model(self) -> str:
        return os.environ.get(self.model_env) or self.default_model


PROVIDERS = {
    "claude": Provider("claude", ("ANTHROPIC_API_KEY",), "SECURITY_AI_CLAUDE_MODEL", "claude-sonnet-5"),
    "gemini": Provider("gemini", ("GEMINI_API_KEY", "GOOGLE_API_KEY"), "SECURITY_AI_GEMINI_MODEL", "gemini-2.5-pro"),
    "openai": Provider("openai", ("OPENAI_API_KEY",), "SECURITY_AI_OPENAI_MODEL", "gpt-5"),
}


class AIError(Exception):
    pass


def available() -> list[Provider]:
    """키가 있는 모델. SECURITY_AI_PROVIDERS=claude,gemini 처럼 좁힐 수 있다."""
    only = {s.strip() for s in os.environ.get("SECURITY_AI_PROVIDERS", "").split(",") if s.strip()}
    return [p for n, p in PROVIDERS.items() if p.key and (not only or n in only)]


def status() -> dict:
    return {n: {"enabled": p in available(), "model": p.model} for n, p in PROVIDERS.items()}


def _post(url: str, body: dict, headers: dict) -> dict:
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raw = e.read()[:2000].decode("utf-8", "replace")
        try:
            err = json.loads(raw).get("error")
            msg = err.get("message") if isinstance(err, dict) else str(err)
        except (ValueError, AttributeError):
            msg = raw
        raise AIError(f"HTTP {e.code}: {' '.join(str(msg).split())[:200]}") from e
    except OSError as e:
        raise AIError(str(e)) from e


def _claude(p: Provider, system: str, prompt: str) -> str:
    r = _post("https://api.anthropic.com/v1/messages",
              {"model": p.model, "max_tokens": 8000, "system": system,
               "messages": [{"role": "user", "content": prompt}]},
              {"x-api-key": p.key, "anthropic-version": "2023-06-01"})
    return "".join(b.get("text", "") for b in r.get("content", []) if b.get("type") == "text")


def _openai(p: Provider, system: str, prompt: str) -> str:
    r = _post("https://api.openai.com/v1/chat/completions",
              {"model": p.model, "response_format": {"type": "json_object"},
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]},
              {"Authorization": f"Bearer {p.key}"})
    return r["choices"][0]["message"]["content"]


def _gemini(p: Provider, system: str, prompt: str) -> str:
    r = _post(f"https://generativelanguage.googleapis.com/v1beta/models/{p.model}:generateContent",
              {"systemInstruction": {"parts": [{"text": system}]},
               "contents": [{"role": "user", "parts": [{"text": prompt}]}],
               "generationConfig": {"responseMimeType": "application/json"}},
              {"x-goog-api-key": p.key})
    return "".join(part.get("text", "") for part in r["candidates"][0]["content"]["parts"])


CALLS = {"claude": _claude, "openai": _openai, "gemini": _gemini}


def parse_json(text: str) -> dict:
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise AIError("JSON 응답이 아닙니다.")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as e:
        raise AIError(f"JSON 해석 실패: {e}") from e


def ask(p: Provider, system: str, prompt: str) -> dict:
    return parse_json(CALLS[p.name](p, system, prompt))


def ask_all(system: str, prompt: str) -> dict[str, dict]:
    """키가 있는 모든 모델에 동시에 묻는다. 실패한 모델은 {"error": ...} 로 돌려준다."""
    providers = available()
    if not providers:
        raise AIError("사용할 AI 모델이 없습니다. ANTHROPIC_API_KEY · GEMINI_API_KEY · OPENAI_API_KEY 중 하나 이상을 설정하세요.")

    def one(p):
        try:
            return p.name, ask(p, system, prompt)
        except (AIError, KeyError, IndexError, TypeError) as e:
            return p.name, {"error": str(e)}

    with ThreadPoolExecutor(len(providers)) as ex:
        return dict(ex.map(one, providers))
