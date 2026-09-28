"""모델 공통 호출. Claude Code CLI(Opus 5.5, 추가 비용 없음) · OpenAI · Gemini 를 모두 지원."""
from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

TIMEOUT = 120


ENV_FILE = Path(__file__).resolve().parents[2] / ".env"   # Security/.env (git 제외)
CLAUDE_BIN = (Path.home() / ".vscode" / "extensions").glob("anthropic.claude-code-*-win32-x64/resources/native-binary/claude.exe")
CLAUDE_BIN = next(CLAUDE_BIN, None)


def load_env_file(path: Path = ENV_FILE) -> None:
    """Security/.env 의 KEY=VALUE 를 환경변수로 (이미 설정된 값은 덮지 않음)."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = v.strip().strip('"').strip("'")
            if v:
                os.environ.setdefault(k.strip(), v)


@dataclass
class Provider:
    name: str
    model_env: str | None
    default_model: str
    key_envs: tuple[str, ...] = ()
    key_prefix: str = ""

    @property
    def key(self) -> str | None:
        if not self.key_envs:
            return None
        return next((os.environ[k] for k in self.key_envs if os.environ.get(k)), None)

    @property
    def key_ok(self) -> bool:
        if self.name == "claude":
            return CLAUDE_BIN and CLAUDE_BIN.exists()
        return bool(self.key) and self.key.startswith(self.key_prefix)

    @property
    def model(self) -> str:
        if self.model_env:
            return os.environ.get(self.model_env) or self.default_model
        return self.default_model


PROVIDERS = {
    "claude": Provider("claude", None, "claude-opus-5-5"),   # Claude Code CLI 사용, 키 불필요
    "gemini": Provider("gemini", "SECURITY_AI_GEMINI_MODEL", "gemini-2.5-pro", ("GEMINI_API_KEY", "GOOGLE_API_KEY"), "AIza"),
    "openai": Provider("openai", "SECURITY_AI_OPENAI_MODEL", "gpt-5", ("OPENAI_API_KEY",), "sk-"),
}


class AIError(Exception):
    pass


def available() -> list[Provider]:
    """형식이 맞는 키가 있는 모델. SECURITY_AI_PROVIDERS=claude,gemini 처럼 좁힐 수 있다."""
    load_env_file()
    only = {s.strip() for s in os.environ.get("SECURITY_AI_PROVIDERS", "").split(",") if s.strip()}
    return [p for n, p in PROVIDERS.items() if p.key_ok and (not only or n in only)]


def status() -> dict:
    enabled = available()
    return {n: {"enabled": p in enabled, "model": p.model,
                "state": "사용" if p in enabled else "키 형식 오류" if p.key else "키 없음"}
            for n, p in PROVIDERS.items()}


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
    try:
        r = subprocess.run([str(CLAUDE_BIN), "-p", "--model", p.model, "--output-format", "json",
                           "--system-prompt", system],
                          input=prompt, capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            raise AIError(f"claude CLI 오류: {r.stderr[:300]}")
        out = json.loads(r.stdout)
        return out.get("message", "")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise AIError(str(e)) from e


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
