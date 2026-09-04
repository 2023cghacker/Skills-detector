"""Provider-isolated structured model calls for static Skill analysis."""

from __future__ import annotations

import json
import os
from typing import Any, Mapping

from jsonschema import ValidationError, validate
from openai import OpenAI


DEFAULT_PROVIDER = "deepseek"
DEFAULT_MODELS = {
    "deepseek": "deepseek-v4-flash",
    "openai": "gpt-5.4-mini-2026-03-17",
}
API_KEY_ENV = {
    "deepseek": "DEEPSEEK_API_KEY",
    "openai": "OPENAI_API_KEY",
}


def default_model(provider: str) -> str:
    try:
        return DEFAULT_MODELS[provider]
    except KeyError as exc:
        raise ValueError(f"unsupported model provider: {provider}") from exc


def require_api_key(provider: str) -> str:
    try:
        variable = API_KEY_ENV[provider]
    except KeyError as exc:
        raise ValueError(f"unsupported model provider: {provider}") from exc
    key = os.getenv(variable)
    if not key:
        raise RuntimeError(f"{variable} is not set")
    return key


def _usage_values(usage: Any, *, chat: bool) -> dict[str, int]:
    if usage is None:
        return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    input_name = "prompt_tokens" if chat else "input_tokens"
    output_name = "completion_tokens" if chat else "output_tokens"
    return {
        "input_tokens": int(getattr(usage, input_name, 0) or 0),
        "output_tokens": int(getattr(usage, output_name, 0) or 0),
        "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
    }


def _decode_and_validate(content: str | None, schema: Mapping[str, Any]) -> dict[str, Any]:
    if not content:
        raise ValueError("model returned no JSON content")
    try:
        result = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("model returned invalid JSON") from exc
    try:
        validate(instance=result, schema=dict(schema))
    except ValidationError as exc:
        raise ValueError(f"model JSON failed local schema validation: {exc.message}") from exc
    return result


def _deepseek_request(
    *, model: str, instructions: str, input_text: str, schema: Mapping[str, Any],
    max_output_tokens: int, timeout: int,
) -> tuple[dict[str, Any], dict[str, int]]:
    client = OpenAI(
        api_key=require_api_key("deepseek"),
        base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        timeout=timeout,
        max_retries=2,
    )
    schema_text = json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
    messages = [
        {
            "role": "system",
            "content": instructions
            + "\nReturn one JSON object matching this JSON Schema exactly:\n"
            + schema_text,
        },
        {"role": "user", "content": input_text},
    ]
    accumulated = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    last_error: ValueError | None = None
    last_finish_reason = "unknown"
    validation_attempts = 3
    for attempt in range(validation_attempts):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            response_format={"type": "json_object"},
            stream=False,
            max_tokens=max_output_tokens,
            temperature=0,
            extra_body={"thinking": {"type": "disabled"}},
        )
        call_usage = _usage_values(response.usage, chat=True)
        for name, value in call_usage.items():
            accumulated[name] += value
        choice = response.choices[0]
        last_finish_reason = str(getattr(choice, "finish_reason", "unknown"))
        try:
            result = _decode_and_validate(choice.message.content, schema)
            return result, accumulated
        except ValueError as exc:
            last_error = exc
            if attempt + 1 < validation_attempts:
                messages.append({
                    "role": "user",
                    "content": (
                        "The previous object did not satisfy the required schema: "
                        f"{exc}. Return a corrected JSON object only; replace null with "
                        "a schema-valid explicit value and include every required field."
                    ),
                })
    raise ValueError(
        f"DeepSeek returned no schema-valid JSON after {validation_attempts} attempts "
        f"(finish_reason={last_finish_reason}): {last_error}"
    )


def _openai_request(
    *, model: str, instructions: str, input_text: str, schema: Mapping[str, Any],
    schema_name: str, max_output_tokens: int, timeout: int,
) -> tuple[dict[str, Any], dict[str, int]]:
    client = OpenAI(
        api_key=require_api_key("openai"),
        base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        timeout=timeout,
        max_retries=2,
    )
    response = client.responses.create(
        model=model,
        instructions=instructions,
        input=input_text,
        reasoning={"effort": "none"},
        store=False,
        max_output_tokens=max_output_tokens,
        text={
            "format": {
                "type": "json_schema",
                "name": schema_name,
                "strict": True,
                "schema": dict(schema),
            }
        },
    )
    result = _decode_and_validate(response.output_text, schema)
    return result, _usage_values(response.usage, chat=False)


def request_json(
    *, provider: str, model: str, instructions: str, input_text: str,
    schema: Mapping[str, Any], schema_name: str, max_output_tokens: int,
    timeout: int,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Return a locally schema-validated object from one supported provider."""
    if provider == "deepseek":
        return _deepseek_request(
            model=model,
            instructions=instructions,
            input_text=input_text,
            schema=schema,
            max_output_tokens=max_output_tokens,
            timeout=timeout,
        )
    if provider == "openai":
        return _openai_request(
            model=model,
            instructions=instructions,
            input_text=input_text,
            schema=schema,
            schema_name=schema_name,
            max_output_tokens=max_output_tokens,
            timeout=timeout,
        )
    raise ValueError(f"unsupported model provider: {provider}")
