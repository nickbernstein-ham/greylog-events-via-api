#!/usr/bin/env python3
"""
Fetch recent Greylog messages, redact PII, enrich them with Ollama, and post
the enriched results back to Greylog.

Supported postback methods:

    syslog_udp  - Send enriched messages to an existing Greylog Syslog UDP input.
    gelf_http   - Send enriched messages to a Greylog GELF HTTP input.

Expected .env example:

    GRAYLOG_TOKEN='your-greylog-token'
    GRAYLOG_URL='https://sip.hamiltoncaptel.com:9000'

    OLLAMA_API_BASE='http://127.0.0.1:11434'
    OLLAMA_MODEL='qwen3:1.7b'

    LOG_LEVEL='INFO'

    POST_OUTPUT_TO_GRAYLOG=true
    GRAYLOG_OUTPUT_STREAM='nick-ollama-out'
    GRAYLOG_OUTPUT_METHOD='syslog_udp'
    GRAYLOG_SYSLOG_HOST='sip.hamiltoncaptel.com'
    GRAYLOG_SYSLOG_PORT='514'

Optional GELF HTTP settings:

    GRAYLOG_OUTPUT_METHOD='gelf_http'
    GRAYLOG_GELF_HTTP_URL='http://sip.hamiltoncaptel.com:12201/gelf'
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import logging
import os
import re
import socket
import sys
from functools import reduce
from typing import Any, Callable, Iterable
from urllib.parse import urljoin

import requests
from requests import Response
from requests.auth import HTTPBasicAuth


DEFAULT_GREYLOG_URL = "https://sip.hamiltoncaptel.com:9000"
DEFAULT_STREAM_NAME = "test"
DEFAULT_OUTPUT_STREAM = "nick-ollama-out"
DEFAULT_OUTPUT_METHOD = "syslog_udp"
DEFAULT_LIMIT = 10
DEFAULT_RANGE_SECONDS = 86_400
DEFAULT_OLLAMA_API_BASE = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "qwen3:1.7b"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_SYSLOG_HOST = "sip.hamiltoncaptel.com"
DEFAULT_SYSLOG_PORT = 514
DEFAULT_MAX_SYSLOG_BYTES = 60_000


JsonDict = dict[str, Any]
Redactor = Callable[[str], tuple[str, tuple[JsonDict, ...]]]


def normalize_greylog_api_url(base_url: str) -> str:
    """Normalize a Greylog base URL so it points at the REST API root.

    Args:
        base_url: Greylog web/API base URL, with or without `/api`.

    Returns:
        A normalized Greylog API URL ending in `/api/`.
    """
    stripped = base_url.rstrip("/")
    api_root = stripped if stripped.endswith("/api") else f"{stripped}/api"
    return f"{api_root}/"


def normalize_base_url(base_url: str) -> str:
    """Normalize a generic base URL by removing trailing slashes.

    Args:
        base_url: URL string to normalize.

    Returns:
        URL string without trailing slashes.
    """
    return base_url.rstrip("/")


def bool_from_env(value: str | None, default: bool) -> bool:
    """Parse a boolean environment-style string.

    Args:
        value: Environment string.
        default: Default value when value is missing.

    Returns:
        Parsed boolean value.
    """
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def int_from_env(value: str | None, default: int) -> int:
    """Parse an integer environment-style string.

    Args:
        value: Environment string.
        default: Default value when value is missing or invalid.

    Returns:
        Parsed integer value.
    """
    if value is None:
        return default

    try:
        return int(value)
    except ValueError:
        return default


def configure_logging(log_level: str) -> logging.Logger:
    """Configure process logging.

    Args:
        log_level: Logging level name, such as DEBUG, INFO, WARNING, or ERROR.

    Returns:
        Configured module logger.
    """
    resolved_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=resolved_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return logging.getLogger("greylog_ollama")


def log_json(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    """Log a structured JSON suffix without logging original message contents.

    Args:
        logger: Logger to write to.
        level: Logging level.
        message: Human-readable log message.
        **fields: Structured fields to serialize.
    """
    logger.log(level, "%s %s", message, json.dumps(fields, sort_keys=True, default=str))


def build_auth(username: str | None, password: str | None, token: str | None) -> HTTPBasicAuth:
    """Build HTTP Basic auth for Greylog.

    Greylog API tokens are normally used as the username, with `token` as the
    password.

    Args:
        username: Greylog username.
        password: Greylog password.
        token: Greylog access token.

    Returns:
        A requests-compatible HTTPBasicAuth object.

    Raises:
        ValueError: If neither token nor username/password credentials are usable.
    """
    if token:
        return HTTPBasicAuth(token, "token")

    if username:
        resolved_password = password or getpass.getpass("Greylog password: ")
        return HTTPBasicAuth(username, resolved_password)

    raise ValueError("Provide --token or --username/--password, or set GRAYLOG_TOKEN.")


def greylog_headers() -> JsonDict:
    """Return standard headers for Greylog API requests.

    Returns:
        A dictionary of HTTP headers.
    """
    return {
        "Accept": "application/json",
        "X-Requested-By": "python-greylog-client",
    }


def get_json(session: requests.Session, url: str, params: JsonDict | None = None) -> JsonDict:
    """Perform a GET request and return the decoded JSON response.

    Args:
        session: Configured requests session.
        url: Fully qualified request URL.
        params: Optional query parameters.

    Returns:
        The decoded JSON response body.

    Raises:
        requests.HTTPError: If the response has an unsuccessful status code.
        ValueError: If the response body is not JSON.
    """
    response: Response = session.get(url, params=params)
    response.raise_for_status()
    return response.json()


def post_json(url: str, payload: JsonDict, timeout: int = 120) -> JsonDict:
    """Perform a JSON POST request and return the decoded JSON response.

    Args:
        url: Fully qualified request URL.
        payload: JSON-serializable request body.
        timeout: Request timeout in seconds.

    Returns:
        The decoded JSON response body.

    Raises:
        requests.HTTPError: If the response has an unsuccessful status code.
        ValueError: If the response body is not JSON.
    """
    response = requests.post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()


def fetch_streams(session: requests.Session, api_url: str) -> tuple[JsonDict, ...]:
    """Fetch all Greylog streams.

    Args:
        session: Configured requests session.
        api_url: Normalized Greylog API URL.

    Returns:
        A tuple of stream objects returned by Greylog.
    """
    payload = get_json(session, urljoin(api_url, "streams"))
    return tuple(payload.get("streams", ()))


def stream_matches_name(stream_name: str, stream: JsonDict) -> bool:
    """Check whether a Greylog stream matches a requested name.

    Args:
        stream_name: Requested stream title/name.
        stream: A stream object returned by Greylog.

    Returns:
        True when the stream title or name matches case-sensitively.
    """
    return stream.get("title") == stream_name or stream.get("name") == stream_name


def find_stream_id(stream_name: str, streams: Iterable[JsonDict]) -> str:
    """Find a Greylog stream ID by stream title/name.

    Args:
        stream_name: Stream title/name to find.
        streams: Iterable of Greylog stream objects.

    Returns:
        The matching stream ID.

    Raises:
        LookupError: If no matching stream is found.
    """
    matches = tuple(stream for stream in streams if stream_matches_name(stream_name, stream))

    if not matches:
        raise LookupError(f"Greylog stream not found: {stream_name!r}")

    return str(matches[0]["id"])


def build_recent_messages_params(stream_id: str, limit: int, range_seconds: int) -> JsonDict:
    """Build Greylog relative-search parameters.

    Args:
        stream_id: Greylog stream ID.
        limit: Maximum number of messages to return.
        range_seconds: Relative time range in seconds.

    Returns:
        Query parameters for Greylog's relative search endpoint.
    """
    return {
        "query": "*",
        "filter": f"streams:{stream_id}",
        "range": range_seconds,
        "limit": limit,
        "sort": "timestamp:desc",
    }


def fetch_recent_stream_messages(
    session: requests.Session,
    api_url: str,
    stream_id: str,
    limit: int,
    range_seconds: int,
) -> tuple[JsonDict, ...]:
    """Fetch recent messages from a Greylog stream.

    Args:
        session: Configured requests session.
        api_url: Normalized Greylog API URL.
        stream_id: Greylog stream ID.
        limit: Number of messages to fetch.
        range_seconds: Relative time window in seconds.

    Returns:
        A tuple of Greylog message wrapper objects.
    """
    payload = get_json(
        session=session,
        url=urljoin(api_url, "search/universal/relative"),
        params=build_recent_messages_params(stream_id, limit, range_seconds),
    )
    return tuple(payload.get("messages", ()))


def simplify_message(wrapper: JsonDict) -> JsonDict:
    """Simplify a Greylog message wrapper for downstream processing.

    Args:
        wrapper: A message wrapper from Greylog's search response.

    Returns:
        A smaller dictionary containing common useful fields.
    """
    message = wrapper.get("message", {})
    return {
        "timestamp": message.get("timestamp"),
        "source": message.get("source"),
        "message": message.get("message"),
        "stream_ids": message.get("streams"),
        "index": wrapper.get("index"),
        "id": wrapper.get("id") or message.get("_id"),
    }


def create_greylog_session(auth: HTTPBasicAuth, verify_tls: bool) -> requests.Session:
    """Create a configured Greylog requests session.

    Args:
        auth: HTTP Basic auth credentials.
        verify_tls: Whether to verify TLS certificates.

    Returns:
        A configured requests Session.
    """
    session = requests.Session()
    session.auth = auth
    session.headers.update(greylog_headers())
    session.verify = verify_tls
    return session


def build_finding(pii_type: str, count: int) -> tuple[JsonDict, ...]:
    """Build a PII finding tuple when a redaction happened.

    Args:
        pii_type: Type of PII detected.
        count: Number of redactions performed.

    Returns:
        A one-item tuple when count is positive, otherwise an empty tuple.
    """
    return ({"type": pii_type, "count": count},) if count > 0 else ()


def regex_redact(
    text: str,
    pii_type: str,
    pattern: str,
    replacement: str,
    flags: int = 0,
) -> tuple[str, tuple[JsonDict, ...]]:
    """Redact text using a regular expression.

    Args:
        text: Input text to redact.
        pii_type: Type of PII being redacted.
        pattern: Regular expression pattern.
        replacement: Replacement text.
        flags: Optional regular expression flags.

    Returns:
        A tuple containing redacted text and finding metadata.
    """
    redacted, count = re.subn(pattern, replacement, text, flags=flags)
    return redacted, build_finding(pii_type, count)


def redact_authorization_headers(text: str) -> tuple[str, tuple[JsonDict, ...]]:
    """Redact Authorization headers.

    Args:
        text: Input text to redact.

    Returns:
        A tuple containing redacted text and finding metadata.
    """
    return regex_redact(
        text=text,
        pii_type="authorization_header",
        pattern=r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+",
        replacement="authorization: [REDACTED_SECRET]",
    )


def redact_secret_key_values(text: str) -> tuple[str, tuple[JsonDict, ...]]:
    """Redact common secret-like key/value pairs.

    Args:
        text: Input text to redact.

    Returns:
        A tuple containing redacted text and finding metadata.
    """
    return regex_redact(
        text=text,
        pii_type="secret",
        pattern=(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
            r"\s*[:=]\s*['\"]?[^'\"\s,;]+"
        ),
        replacement=r"\1=[REDACTED_SECRET]",
    )


def redact_emails(text: str) -> tuple[str, tuple[JsonDict, ...]]:
    """Redact email addresses.

    Args:
        text: Input text to redact.

    Returns:
        A tuple containing redacted text and finding metadata.
    """
    return regex_redact(
        text=text,
        pii_type="email",
        pattern=r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.+-])",
        replacement="[REDACTED_EMAIL]",
    )


def redact_ssns(text: str) -> tuple[str, tuple[JsonDict, ...]]:
    """Redact US Social Security numbers.

    Args:
        text: Input text to redact.

    Returns:
        A tuple containing redacted text and finding metadata.
    """
    return regex_redact(
        text=text,
        pii_type="ssn",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        replacement="[REDACTED_SSN]",
    )


def redact_phone_numbers(text: str) -> tuple[str, tuple[JsonDict, ...]]:
    """Redact likely US phone numbers.

    Args:
        text: Input text to redact.

    Returns:
        A tuple containing redacted text and finding metadata.
    """
    return regex_redact(
        text=text,
        pii_type="phone",
        pattern=r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)",
        replacement="[REDACTED_PHONE]",
    )


def redact_ipv4_addresses(text: str) -> tuple[str, tuple[JsonDict, ...]]:
    """Redact IPv4 addresses.

    Args:
        text: Input text to redact.

    Returns:
        A tuple containing redacted text and finding metadata.
    """
    return regex_redact(
        text=text,
        pii_type="ipv4_address",
        pattern=(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        replacement="[REDACTED_IP]",
    )


def redact_mac_addresses(text: str) -> tuple[str, tuple[JsonDict, ...]]:
    """Redact MAC addresses.

    Args:
        text: Input text to redact.

    Returns:
        A tuple containing redacted text and finding metadata.
    """
    return regex_redact(
        text=text,
        pii_type="mac_address",
        pattern=r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
        replacement="[REDACTED_MAC]",
    )


def digits_only(value: str) -> str:
    """Extract only numeric digits from a string.

    Args:
        value: Input string.

    Returns:
        A string containing only digits.
    """
    return "".join(character for character in value if character.isdigit())


def luhn_checksum(number: str) -> int:
    """Calculate a Luhn checksum.

    Args:
        number: Numeric string to validate.

    Returns:
        The Luhn checksum modulo 10.
    """
    digits = tuple(int(digit) for digit in number)
    parity = len(digits) % 2

    def transformed(index_and_digit: tuple[int, int]) -> int:
        """Transform one digit according to the Luhn algorithm.

        Args:
            index_and_digit: Tuple containing a digit index and digit value.

        Returns:
            The transformed digit value.
        """
        index, digit = index_and_digit
        doubled = digit * 2 if index % 2 == parity else digit
        return doubled - 9 if doubled > 9 else doubled

    return sum(map(transformed, enumerate(digits))) % 10


def is_likely_credit_card(candidate: str) -> bool:
    """Check whether a string looks like a credit card number.

    Args:
        candidate: Candidate credit card string.

    Returns:
        True if the candidate has a valid length and Luhn checksum.
    """
    number = digits_only(candidate)
    return 13 <= len(number) <= 19 and luhn_checksum(number) == 0


def redact_credit_cards(text: str) -> tuple[str, tuple[JsonDict, ...]]:
    """Redact likely credit card numbers using length and Luhn checks.

    Args:
        text: Input text to redact.

    Returns:
        A tuple containing redacted text and finding metadata.
    """
    count = 0

    def replace_if_credit_card(match: re.Match[str]) -> str:
        """Replace a regex match only if it passes credit-card validation.

        Args:
            match: Regex match containing a candidate credit card number.

        Returns:
            Redaction marker or original matched text.
        """
        nonlocal count
        candidate = match.group(0)
        if is_likely_credit_card(candidate):
            count += 1
            return "[REDACTED_CREDIT_CARD]"
        return candidate

    redacted = re.sub(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", replace_if_credit_card, text)
    return redacted, build_finding("credit_card", count)


def pii_redactors() -> tuple[Redactor, ...]:
    """Return the ordered PII redaction pipeline.

    Returns:
        A tuple of redactor functions.
    """
    return (
        redact_authorization_headers,
        redact_secret_key_values,
        redact_emails,
        redact_ssns,
        redact_phone_numbers,
        redact_credit_cards,
        redact_mac_addresses,
        redact_ipv4_addresses,
    )


def apply_redactor(
    state: tuple[str, tuple[JsonDict, ...]],
    redactor: Redactor,
) -> tuple[str, tuple[JsonDict, ...]]:
    """Apply a redactor to accumulated redaction state.

    Args:
        state: Current redacted text and accumulated findings.
        redactor: Redaction function to apply.

    Returns:
        Updated redaction state.
    """
    current_text, current_findings = state
    redacted_text, new_findings = redactor(current_text)
    return redacted_text, current_findings + new_findings


def redact_pii(text: str) -> JsonDict:
    """Detect and redact common PII from a log message.

    Args:
        text: Original log message.

    Returns:
        A dictionary containing redaction status, findings, and redacted text.
    """
    redacted_text, findings = reduce(apply_redactor, pii_redactors(), (text, ()))
    return {
        "pii_detected": bool(findings),
        "findings": list(findings),
        "redacted_text": redacted_text,
    }


def pii_tool_schema() -> JsonDict:
    """Build the Ollama tool schema for PII redaction.

    Returns:
        A JSON schema describing the redaction tool.
    """
    return {
        "type": "function",
        "function": {
            "name": "redact_pii",
            "description": "Detect and redact personally identifiable information in a log message.",
            "parameters": {
                "type": "object",
                "required": ["text"],
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The original log message to inspect and redact.",
                    }
                },
            },
        },
    }


def context_output_schema() -> JsonDict:
    """Build the JSON schema for Ollama context enrichment.

    Returns:
        A JSON schema for structured enrichment output.
    """
    return {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "likely_component": {"type": "string"},
            "likely_event_type": {"type": "string"},
            "severity_hint": {
                "type": "string",
                "enum": ["low", "medium", "high", "unknown"],
            },
            "context": {"type": "string"},
            "recommended_next_steps": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "required": [
            "summary",
            "likely_component",
            "likely_event_type",
            "severity_hint",
            "context",
            "recommended_next_steps",
        ],
    }


def ollama_chat_url(ollama_api_base: str) -> str:
    """Build the Ollama chat endpoint URL.

    Args:
        ollama_api_base: Ollama API base URL.

    Returns:
        Fully qualified `/api/chat` URL.
    """
    return f"{normalize_base_url(ollama_api_base)}/api/chat"


def build_redaction_messages(log_text: str) -> list[JsonDict]:
    """Build messages for asking the model to call the redaction tool.

    Args:
        log_text: Original log message text.

    Returns:
        Chat messages for the redaction-tool request.
    """
    return [
        {
            "role": "system",
            "content": (
                "You analyze log messages. Your first step must be to call the "
                "`redact_pii` tool exactly once using the original log message. "
                "Do not attempt to redact the text yourself."
            ),
        },
        {
            "role": "user",
            "content": f"Inspect and redact this log message:\n\n{log_text}",
        },
    ]


def call_ollama(
    ollama_api_base: str,
    model: str,
    messages: list[JsonDict],
    tools: list[JsonDict] | None = None,
    response_format: JsonDict | str | None = None,
) -> JsonDict:
    """Call Ollama's chat API.

    Args:
        ollama_api_base: Ollama API base URL.
        model: Ollama model name.
        messages: Chat messages.
        tools: Optional tool definitions.
        response_format: Optional Ollama `format` value.

    Returns:
        Decoded Ollama response.
    """
    payload: JsonDict = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0},
    }

    if tools:
        payload["tools"] = tools

    if response_format:
        payload["format"] = response_format

    return post_json(ollama_chat_url(ollama_api_base), payload)


def extract_tool_calls(ollama_response: JsonDict) -> tuple[JsonDict, ...]:
    """Extract tool calls from an Ollama chat response.

    Args:
        ollama_response: Decoded Ollama response.

    Returns:
        A tuple of tool-call dictionaries.
    """
    message = ollama_response.get("message", {})
    return tuple(message.get("tool_calls", ()))


def parse_tool_arguments(tool_call: JsonDict) -> JsonDict:
    """Parse a tool call's function arguments.

    Args:
        tool_call: Tool-call dictionary from Ollama.

    Returns:
        Parsed argument dictionary.
    """
    arguments = tool_call.get("function", {}).get("arguments", {})
    if isinstance(arguments, str):
        return json.loads(arguments)
    return arguments if isinstance(arguments, dict) else {}


def tool_name(tool_call: JsonDict) -> str:
    """Return the function name from a tool call.

    Args:
        tool_call: Tool-call dictionary from Ollama.

    Returns:
        Function name, or an empty string when missing.
    """
    return str(tool_call.get("function", {}).get("name", ""))


def execute_redaction_tool(tool_call: JsonDict, fallback_text: str) -> JsonDict:
    """Execute the requested redaction tool.

    Args:
        tool_call: Tool-call dictionary from Ollama.
        fallback_text: Text to redact if the tool call omits arguments.

    Returns:
        Redaction result dictionary.

    Raises:
        ValueError: If the model requests an unsupported tool.
    """
    if tool_name(tool_call) != "redact_pii":
        raise ValueError(f"Unsupported tool call: {tool_name(tool_call)!r}")

    arguments = parse_tool_arguments(tool_call)
    text = str(arguments.get("text") or fallback_text)
    return redact_pii(text)


def build_tool_result_message(name: str, result: JsonDict) -> JsonDict:
    """Build a tool-result message for Ollama.

    Args:
        name: Tool name.
        result: Tool execution result.

    Returns:
        Tool-result message.
    """
    return {
        "role": "tool",
        "tool_name": name,
        "content": json.dumps(result, sort_keys=True),
    }


def call_redaction_tool_via_ollama(
    ollama_api_base: str,
    model: str,
    log_text: str,
) -> tuple[JsonDict, bool, list[JsonDict]]:
    """Ask Ollama to request PII redaction and execute the tool.

    Args:
        ollama_api_base: Ollama API base URL.
        model: Ollama model name.
        log_text: Original log message text.

    Returns:
        Redaction result, whether the model requested the tool, and chat history.
    """
    messages = build_redaction_messages(log_text)
    response = call_ollama(
        ollama_api_base=ollama_api_base,
        model=model,
        messages=messages,
        tools=[pii_tool_schema()],
    )
    tool_calls = extract_tool_calls(response)

    if not tool_calls:
        redaction = redact_pii(log_text)
        return redaction, False, messages + [build_tool_result_message("redact_pii", redaction)]

    first_call = tool_calls[0]
    redaction = execute_redaction_tool(first_call, fallback_text=log_text)
    assistant_message = response.get("message", {})
    tool_message = build_tool_result_message(tool_name(first_call), redaction)

    return redaction, True, messages + [assistant_message, tool_message]


def build_context_messages(
    base_messages: list[JsonDict],
    message: JsonDict,
    redaction: JsonDict,
) -> list[JsonDict]:
    """Build messages for contextual log enrichment.

    Args:
        base_messages: Prior messages, including any tool-call transcript.
        message: Simplified Greylog message.
        redaction: PII redaction result.

    Returns:
        Chat messages for structured contextual enrichment.
    """
    enrichment_request = {
        "greylog_metadata": {
            "timestamp": message.get("timestamp"),
            "source": message.get("source"),
            "index": message.get("index"),
            "id": message.get("id"),
        },
        "pii_detected": redaction["pii_detected"],
        "pii_findings": redaction["findings"],
        "redacted_message": redaction["redacted_text"],
    }

    return base_messages + [
        {
            "role": "user",
            "content": (
                "Using only the redacted log message and metadata below, add concise "
                "operational context. Do not reconstruct or guess redacted values. "
                "Return only JSON matching the requested schema.\n\n"
                f"{json.dumps(enrichment_request, indent=2, sort_keys=True)}"
            ),
        }
    ]


def parse_json_content(response: JsonDict) -> JsonDict:
    """Parse JSON content from an Ollama response.

    Args:
        response: Decoded Ollama chat response.

    Returns:
        Parsed JSON object.

    Raises:
        ValueError: If the response message content is missing.
        json.JSONDecodeError: If the response message content is invalid JSON.
    """
    content = response.get("message", {}).get("content", "")
    if not content:
        raise ValueError("Ollama returned empty content.")
    return json.loads(content)


def fallback_context(redacted_text: str, reason: str) -> JsonDict:
    """Build fallback context when model enrichment fails.

    Args:
        redacted_text: Redacted log message.
        reason: Reason enrichment failed.

    Returns:
        Conservative context dictionary.
    """
    return {
        "summary": redacted_text[:240],
        "likely_component": "unknown",
        "likely_event_type": "unknown",
        "severity_hint": "unknown",
        "context": f"Model enrichment failed: {reason}",
        "recommended_next_steps": ["Review the redacted log message manually."],
    }


def enrich_context_with_ollama(
    ollama_api_base: str,
    model: str,
    base_messages: list[JsonDict],
    message: JsonDict,
    redaction: JsonDict,
) -> JsonDict:
    """Ask Ollama to add structured context to a redacted log message.

    Args:
        ollama_api_base: Ollama API base URL.
        model: Ollama model name.
        base_messages: Prior messages, including tool result.
        message: Simplified Greylog message.
        redaction: PII redaction result.

    Returns:
        Structured context dictionary.
    """
    try:
        response = call_ollama(
            ollama_api_base=ollama_api_base,
            model=model,
            messages=build_context_messages(base_messages, message, redaction),
            response_format=context_output_schema(),
        )
        return parse_json_content(response)
    except Exception as exc:
        return fallback_context(redaction["redacted_text"], str(exc))


def enrich_message(
    ollama_api_base: str,
    model: str,
    message: JsonDict,
) -> JsonDict:
    """Redact and enrich one Greylog message.

    Args:
        ollama_api_base: Ollama API base URL.
        model: Ollama model name.
        message: Simplified Greylog message.

    Returns:
        Enriched message dictionary.
    """
    log_text = str(message.get("message") or "")
    redaction, tool_requested, tool_messages = call_redaction_tool_via_ollama(
        ollama_api_base=ollama_api_base,
        model=model,
        log_text=log_text,
    )
    context = enrich_context_with_ollama(
        ollama_api_base=ollama_api_base,
        model=model,
        base_messages=tool_messages,
        message=message,
        redaction=redaction,
    )

    return {
        **message,
        "message": redaction["redacted_text"],
        "pii": {
            "detected": redaction["pii_detected"],
            "findings": redaction["findings"],
        },
        "context": context,
        "ollama": {
            "model": model,
            "redaction_tool_requested": tool_requested,
        },
    }


def severity_to_syslog_level(severity_hint: str) -> int:
    """Map enrichment severity to a GELF/syslog numeric level.

    Args:
        severity_hint: Enrichment severity hint.

    Returns:
        Numeric syslog level.
    """
    return {
        "high": 3,
        "medium": 4,
        "low": 6,
        "unknown": 5,
    }.get(severity_hint, 5)


def rfc3339_utc_now() -> str:
    """Return the current UTC timestamp in RFC3339 format.

    Returns:
        Current UTC timestamp string.
    """
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")


def sanitize_syslog_value(value: Any) -> str:
    """Sanitize a value for quoted syslog-style key/value output.

    Args:
        value: Value to sanitize.

    Returns:
        String safe enough for quoted syslog-style key/value output.
    """
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def truncate_utf8_bytes(text: str, max_bytes: int) -> str:
    """Truncate text to a maximum UTF-8 byte size.

    Args:
        text: Text to truncate.
        max_bytes: Maximum UTF-8 byte length.

    Returns:
        Text truncated at a valid UTF-8 boundary.
    """
    encoded = text.encode("utf-8")

    if len(encoded) <= max_bytes:
        return text

    truncated = encoded[:max_bytes]
    return truncated.decode("utf-8", errors="ignore") + "...[TRUNCATED]"


def build_syslog_fields(enriched_message: JsonDict, output_stream: str) -> JsonDict:
    """Build syslog key/value fields for enriched messages.

    Args:
        enriched_message: Enriched message dictionary.
        output_stream: Desired Greylog output stream name.

    Returns:
        Dictionary of fields to place in the syslog message body.
    """
    context = enriched_message.get("context", {})
    return {
        "ollama_output_stream": output_stream,
        "pipeline": "greylog-ollama-enrichment",
        "original_greylog_id": enriched_message.get("id"),
        "original_greylog_index": enriched_message.get("index"),
        "original_source": enriched_message.get("source"),
        "original_timestamp": enriched_message.get("timestamp"),
        "pii_detected": enriched_message.get("pii", {}).get("detected", False),
        "ollama_model": enriched_message.get("ollama", {}).get("model"),
        "likely_component": context.get("likely_component"),
        "likely_event_type": context.get("likely_event_type"),
        "severity_hint": context.get("severity_hint", "unknown"),
    }


def build_syslog_field_text(fields: JsonDict) -> str:
    """Build a quoted key/value string for syslog message content.

    Args:
        fields: Field dictionary.

    Returns:
        Space-separated quoted key/value string.
    """
    return " ".join(
        f'{key}="{sanitize_syslog_value(value)}"'
        for key, value in fields.items()
        if value is not None
    )


def build_syslog_message(
    enriched_message: JsonDict,
    output_stream: str,
    host: str,
    max_bytes: int,
) -> str:
    """Build a syslog message containing enriched log context.

    Args:
        enriched_message: Enriched message dictionary.
        output_stream: Desired Greylog output stream name.
        host: Hostname to use in the syslog message.
        max_bytes: Maximum message size in bytes.

    Returns:
        RFC5424-ish syslog message string.
    """
    context = enriched_message.get("context", {})
    severity_hint = str(context.get("severity_hint", "unknown"))
    priority = severity_to_syslog_level(severity_hint)
    summary = str(context.get("summary") or "Ollama-enriched Greylog event")
    fields = build_syslog_fields(enriched_message, output_stream)

    base_message = (
        f"<{priority}>1 {rfc3339_utc_now()} {host} greylog-ollama - - - "
        f"{build_syslog_field_text(fields)} "
        f'summary="{sanitize_syslog_value(summary)}" '
    )

    full_json = json.dumps(enriched_message, sort_keys=True, default=str)
    remaining_bytes = max(max_bytes - len(base_message.encode("utf-8")) - 32, 0)
    truncated_json = truncate_utf8_bytes(full_json, remaining_bytes)

    return (
        f"{base_message}"
        f'enriched_json="{sanitize_syslog_value(truncated_json)}"'
    )


def send_syslog_udp(host: str, port: int, message: str) -> JsonDict:
    """Send one syslog message over UDP.

    Args:
        host: Syslog destination host.
        port: Syslog destination UDP port.
        message: Syslog message string.

    Returns:
        Send result metadata.
    """
    encoded = message.encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(encoded, (host, port))

    return {
        "posted": True,
        "method": "syslog_udp",
        "host": host,
        "port": port,
        "bytes": len(encoded),
    }


def post_syslog_udp_message(
    enriched_message: JsonDict,
    output_stream: str,
    syslog_host: str,
    syslog_port: int,
    output_host: str,
    max_bytes: int,
) -> JsonDict:
    """Post one enriched message to Greylog through Syslog UDP.

    Args:
        enriched_message: Enriched message dictionary.
        output_stream: Desired Greylog output stream name.
        syslog_host: Greylog syslog UDP input host.
        syslog_port: Greylog syslog UDP input port.
        output_host: Hostname to put in the syslog message.
        max_bytes: Maximum syslog message size in bytes.

    Returns:
        Send result metadata.
    """
    message = build_syslog_message(
        enriched_message=enriched_message,
        output_stream=output_stream,
        host=output_host,
        max_bytes=max_bytes,
    )
    return send_syslog_udp(syslog_host, syslog_port, message)


def build_gelf_payload(enriched_message: JsonDict, output_stream: str, host: str) -> JsonDict:
    """Build a GELF payload for posting enriched logs back to Greylog.

    Args:
        enriched_message: Enriched message dictionary.
        output_stream: Desired output stream name.
        host: Host value to use in the GELF message.

    Returns:
        GELF-compatible JSON payload.
    """
    context = enriched_message.get("context", {})
    severity_hint = str(context.get("severity_hint", "unknown"))
    summary = str(context.get("summary") or "Ollama-enriched Greylog event")

    return {
        "version": "1.1",
        "host": host,
        "short_message": summary[:250],
        "full_message": json.dumps(enriched_message, sort_keys=True, default=str),
        "level": severity_to_syslog_level(severity_hint),
        "_ollama_output_stream": output_stream,
        "_pipeline": "greylog-ollama-enrichment",
        "_original_greylog_id": enriched_message.get("id"),
        "_original_greylog_index": enriched_message.get("index"),
        "_original_source": enriched_message.get("source"),
        "_original_timestamp": enriched_message.get("timestamp"),
        "_pii_detected": enriched_message.get("pii", {}).get("detected", False),
        "_ollama_model": enriched_message.get("ollama", {}).get("model"),
        "_likely_component": context.get("likely_component"),
        "_likely_event_type": context.get("likely_event_type"),
        "_severity_hint": severity_hint,
    }


def post_gelf_payload(
    gelf_http_url: str,
    payload: JsonDict,
    verify_tls: bool,
    timeout: int = 30,
) -> JsonDict:
    """Post a GELF payload to Greylog.

    Args:
        gelf_http_url: GELF HTTP input URL.
        payload: GELF-compatible JSON payload.
        verify_tls: Whether to verify TLS certificates.
        timeout: HTTP timeout in seconds.

    Returns:
        Post result metadata.
    """
    response = requests.post(
        gelf_http_url,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=timeout,
        verify=verify_tls,
    )
    response.raise_for_status()
    return {
        "posted": True,
        "method": "gelf_http",
        "status_code": response.status_code,
        "url": gelf_http_url,
    }


def post_gelf_http_message(
    enriched_message: JsonDict,
    gelf_http_url: str,
    output_stream: str,
    host: str,
    verify_tls: bool,
) -> JsonDict:
    """Post one enriched message to Greylog through GELF HTTP.

    Args:
        enriched_message: Enriched message dictionary.
        gelf_http_url: GELF HTTP input URL.
        output_stream: Desired output stream name.
        host: Host value to use in the GELF message.
        verify_tls: Whether to verify TLS certificates.

    Returns:
        Post result metadata.
    """
    payload = build_gelf_payload(enriched_message, output_stream, host)
    return post_gelf_payload(gelf_http_url, payload, verify_tls)


def fetch_greylog_messages(args: argparse.Namespace) -> tuple[JsonDict, ...]:
    """Fetch and simplify recent Greylog messages.

    Args:
        args: Parsed command-line arguments.

    Returns:
        A tuple of simplified Greylog messages.
    """
    api_url = normalize_greylog_api_url(args.url)
    auth = build_auth(args.username, args.password, args.token)
    session = create_greylog_session(auth=auth, verify_tls=not args.insecure)

    stream_id = find_stream_id(args.stream, fetch_streams(session, api_url))
    wrappers = fetch_recent_stream_messages(
        session=session,
        api_url=api_url,
        stream_id=stream_id,
        limit=args.limit,
        range_seconds=args.range_seconds,
    )

    return tuple(map(simplify_message, wrappers))


def maybe_post_enriched_message(args: argparse.Namespace, enriched_message: JsonDict) -> JsonDict:
    """Post an enriched message if output posting is enabled.

    Args:
        args: Parsed command-line arguments.
        enriched_message: Enriched message dictionary.

    Returns:
        Post result metadata.
    """
    if not args.post_output:
        return {"posted": False, "reason": "disabled"}

    if args.output_method == "syslog_udp":
        return post_syslog_udp_message(
            enriched_message=enriched_message,
            output_stream=args.output_stream,
            syslog_host=args.syslog_host,
            syslog_port=args.syslog_port,
            output_host=args.output_host,
            max_bytes=args.max_syslog_bytes,
        )

    if args.output_method == "gelf_http":
        if not args.gelf_http_url:
            return {"posted": False, "reason": "missing_gelf_http_url"}

        return post_gelf_http_message(
            enriched_message=enriched_message,
            gelf_http_url=args.gelf_http_url,
            output_stream=args.output_stream,
            host=args.output_host,
            verify_tls=not args.insecure_gelf,
        )

    return {
        "posted": False,
        "reason": f"unsupported_output_method:{args.output_method}",
    }


def process_message(
    args: argparse.Namespace,
    logger: logging.Logger,
    ordinal: int,
    total: int,
    message: JsonDict,
) -> JsonDict:
    """Process one Greylog message through enrichment and optional postback.

    Args:
        args: Parsed command-line arguments.
        logger: Logger to use.
        ordinal: One-based message number.
        total: Total message count.
        message: Simplified Greylog message.

    Returns:
        Enriched message with postback metadata.
    """
    log_json(
        logger,
        logging.INFO,
        "processing_message_start",
        ordinal=ordinal,
        total=total,
        id=message.get("id"),
        source=message.get("source"),
        timestamp=message.get("timestamp"),
    )

    enriched = enrich_message(
        ollama_api_base=args.ollama_api_base,
        model=args.ollama_model,
        message=message,
    )

    log_json(
        logger,
        logging.INFO,
        "processing_message_enriched",
        ordinal=ordinal,
        total=total,
        id=enriched.get("id"),
        pii_detected=enriched.get("pii", {}).get("detected"),
        pii_findings=enriched.get("pii", {}).get("findings"),
        severity=enriched.get("context", {}).get("severity_hint"),
        redaction_tool_requested=enriched.get("ollama", {}).get("redaction_tool_requested"),
    )

    postback = maybe_post_enriched_message(args, enriched)

    log_json(
        logger,
        logging.INFO,
        "processing_message_postback",
        ordinal=ordinal,
        total=total,
        id=enriched.get("id"),
        posted=postback.get("posted"),
        method=postback.get("method"),
        status_code=postback.get("status_code"),
        reason=postback.get("reason"),
        output_stream=args.output_stream,
    )

    return {**enriched, "postback": postback}


def process_messages(
    args: argparse.Namespace,
    logger: logging.Logger,
    messages: tuple[JsonDict, ...],
) -> tuple[JsonDict, ...]:
    """Process all Greylog messages sequentially.

    Args:
        args: Parsed command-line arguments.
        logger: Logger to use.
        messages: Simplified Greylog messages.

    Returns:
        Tuple of enriched messages with postback metadata.
    """
    total = len(messages)
    return tuple(
        process_message(args, logger, ordinal, total, message)
        for ordinal, message in enumerate(messages, start=1)
    )


def run(args: argparse.Namespace, logger: logging.Logger) -> tuple[JsonDict, ...]:
    """Run the Greylog fetch, enrichment, and postback workflow.

    Args:
        args: Parsed command-line arguments.
        logger: Logger to use.

    Returns:
        A tuple of enriched Greylog message dictionaries.
    """
    log_json(
        logger,
        logging.INFO,
        "run_start",
        stream=args.stream,
        limit=args.limit,
        output_stream=args.output_stream,
        output_method=args.output_method,
        post_output=args.post_output,
        gelf_http_url_configured=bool(args.gelf_http_url),
        syslog_host=args.syslog_host,
        syslog_port=args.syslog_port,
        ollama_model=args.ollama_model,
    )

    messages = fetch_greylog_messages(args)

    log_json(
        logger,
        logging.INFO,
        "greylog_messages_fetched",
        count=len(messages),
        stream=args.stream,
    )

    results = process_messages(args, logger, messages)

    log_json(
        logger,
        logging.INFO,
        "run_complete",
        processed=len(results),
        posted=sum(1 for result in results if result.get("postback", {}).get("posted")),
    )

    return results


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Command-line arguments excluding the executable name.

    Returns:
        Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Fetch Greylog messages, redact PII, add Ollama context, "
            "and post enriched output back to Greylog."
        )
    )

    parser.add_argument("--url", default=os.getenv("GRAYLOG_URL", DEFAULT_GREYLOG_URL))
    parser.add_argument("--stream", default=os.getenv("GRAYLOG_STREAM", DEFAULT_STREAM_NAME))
    parser.add_argument("--limit", type=int, default=int_from_env(os.getenv("GRAYLOG_LIMIT"), DEFAULT_LIMIT))
    parser.add_argument(
        "--range-seconds",
        type=int,
        default=int_from_env(os.getenv("GRAYLOG_RANGE_SECONDS"), DEFAULT_RANGE_SECONDS),
    )

    parser.add_argument("--username", default=os.getenv("GRAYLOG_USERNAME"))
    parser.add_argument("--password", default=os.getenv("GRAYLOG_PASSWORD"))
    parser.add_argument("--token", default=os.getenv("GRAYLOG_TOKEN"))

    parser.add_argument(
        "--ollama-api-base",
        default=os.getenv("OLLAMA_API_BASE", DEFAULT_OLLAMA_API_BASE),
    )
    parser.add_argument(
        "--ollama-model",
        default=os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL),
    )

    parser.add_argument(
        "--output-stream",
        default=os.getenv("GRAYLOG_OUTPUT_STREAM", DEFAULT_OUTPUT_STREAM),
    )
    parser.add_argument(
        "--output-method",
        choices=("syslog_udp", "gelf_http"),
        default=os.getenv("GRAYLOG_OUTPUT_METHOD", DEFAULT_OUTPUT_METHOD),
    )
    parser.add_argument(
        "--syslog-host",
        default=os.getenv("GRAYLOG_SYSLOG_HOST", DEFAULT_SYSLOG_HOST),
    )
    parser.add_argument(
        "--syslog-port",
        type=int,
        default=int_from_env(os.getenv("GRAYLOG_SYSLOG_PORT"), DEFAULT_SYSLOG_PORT),
    )
    parser.add_argument(
        "--max-syslog-bytes",
        type=int,
        default=int_from_env(os.getenv("MAX_SYSLOG_BYTES"), DEFAULT_MAX_SYSLOG_BYTES),
    )
    parser.add_argument("--gelf-http-url", default=os.getenv("GRAYLOG_GELF_HTTP_URL"))

    parser.add_argument(
        "--output-host",
        default=os.getenv("GRAYLOG_OUTPUT_HOST", socket.gethostname()),
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL),
    )

    parser.add_argument(
        "--post-output",
        dest="post_output",
        action="store_true",
        default=bool_from_env(os.getenv("POST_OUTPUT_TO_GRAYLOG"), True),
    )
    parser.add_argument(
        "--no-post-output",
        dest="post_output",
        action="store_false",
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable Greylog API TLS certificate verification.",
    )
    parser.add_argument(
        "--insecure-gelf",
        action="store_true",
        help="Disable GELF HTTP TLS certificate verification.",
    )

    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Program entrypoint.

    Args:
        argv: Command-line arguments excluding the executable name.

    Returns:
        Process exit code.
    """
    args = parse_args(argv)
    logger = configure_logging(args.log_level)

    try:
        results = run(args, logger)
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        log_json(logger, logging.ERROR, "run_failed", error=str(exc))
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
