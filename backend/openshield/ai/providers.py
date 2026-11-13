import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_RESPONSE_BYTES = 256 * 1024


class AIProviderError(RuntimeError):
    pass


def _request_json(
    url: str, *, method: str = "POST", headers: dict[str, str] | None = None,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={"Accept": "application/json", **(headers or {})},
        method=method,
    )
    try:
        with urlopen(request, timeout=45) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise AIProviderError(f"AI provider returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise AIProviderError("Unable to reach AI provider") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AIProviderError("AI provider response exceeds 256 KiB")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AIProviderError("AI provider returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise AIProviderError("AI provider returned an unexpected response")
    if "error" in result:
        raise AIProviderError("AI provider reported a request error")
    return result


def validate_ollama_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"} or not parsed.netloc
        or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        raise ValueError("Ollama URL must be an absolute HTTP(S) URL without credentials")
    return base_url.rstrip("/")


def test_ollama(base_url: str) -> list[str]:
    endpoint = validate_ollama_url(base_url) + "/api/tags"
    result = _request_json(endpoint, method="GET")
    models = result.get("models", [])
    if not isinstance(models, list):
        raise AIProviderError("Ollama returned an invalid model list")
    return [
        item.get("name") for item in models
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ][:100]


def generate_ollama(
    base_url: str, model: str, instructions: str, context: dict[str, object]
) -> str:
    endpoint = validate_ollama_url(base_url) + "/api/chat"
    result = _request_json(
        endpoint,
        headers={"Content-Type": "application/json"},
        payload={
            "model": model,
            "messages": [
                {"role": "system", "content": instructions},
                {"role": "user", "content": json.dumps(context, separators=(",", ":"), sort_keys=True)},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_predict": 1200},
        },
    )
    message = result.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise AIProviderError("Ollama returned an empty investigation")
    return content


def test_openai(api_key: str) -> list[str]:
    if not api_key:
        raise AIProviderError("OpenAI API key is not configured")
    result = _request_json(
        "https://api.openai.com/v1/models",
        method="GET",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    models = result.get("data", [])
    if not isinstance(models, list):
        raise AIProviderError("OpenAI returned an invalid model list")
    return [
        item.get("id") for item in models
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ][:100]


def generate_openai(
    api_key: str, model: str, instructions: str, context: dict[str, object]
) -> str:
    if not api_key:
        raise AIProviderError("OpenAI API key is not configured")
    result = _request_json(
        "https://api.openai.com/v1/responses",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        payload={
            "model": model,
            "instructions": instructions,
            "input": json.dumps(context, separators=(",", ":"), sort_keys=True),
            "max_output_tokens": 1200,
            "text": {"format": {"type": "json_object"}},
        },
    )
    output_text = result.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text
    output = result.get("output", [])
    chunks = []
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            content = item.get("content", [])
            if not isinstance(content, list):
                continue
            for part in content:
                if isinstance(part, dict) and part.get("type") == "output_text":
                    text = part.get("text")
                    if isinstance(text, str):
                        chunks.append(text)
    if not chunks:
        raise AIProviderError("OpenAI returned no text output")
    return "\n".join(chunks)
