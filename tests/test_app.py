import argparse
import json
import socket

import pytest

import app


def sample_enriched_message():
    """Build a representative enriched message for tests."""
    return {
        "id": "msg-1",
        "index": "graylog_0",
        "source": "server01",
        "timestamp": "2026-05-18T12:00:00.000Z",
        "message": "redacted message",
        "stream_ids": ["stream-1"],
        "pii": {
            "detected": True,
            "findings": [{"type": "email", "count": 1}],
        },
        "ollama": {
            "model": "qwen3:1.7b",
            "redaction_tool_requested": True,
        },
        "context": {
            "summary": "Test summary",
            "likely_component": "sip",
            "likely_event_type": "auth_failure",
            "severity_hint": "medium",
            "context": "Useful context",
            "recommended_next_steps": ["Check authentication source."],
        },
    }


def test_normalize_greylog_api_url_adds_api_suffix():
    assert (
        app.normalize_greylog_api_url("https://sip.hamiltoncaptel.com:9000")
        == "https://sip.hamiltoncaptel.com:9000/api/"
    )


def test_normalize_greylog_api_url_preserves_existing_api_suffix():
    assert (
        app.normalize_greylog_api_url("https://sip.hamiltoncaptel.com:9000/api")
        == "https://sip.hamiltoncaptel.com:9000/api/"
    )


def test_normalize_base_url_strips_trailing_slash():
    assert app.normalize_base_url("http://127.0.0.1:11434/") == "http://127.0.0.1:11434"


def test_bool_from_env_defaults_when_missing():
    assert app.bool_from_env(None, True) is True
    assert app.bool_from_env(None, False) is False


def test_bool_from_env_parses_true_values():
    assert app.bool_from_env("true", False) is True
    assert app.bool_from_env("1", False) is True
    assert app.bool_from_env("yes", False) is True
    assert app.bool_from_env("on", False) is True


def test_bool_from_env_parses_false_values():
    assert app.bool_from_env("false", True) is False
    assert app.bool_from_env("0", True) is False
    assert app.bool_from_env("no", True) is False
    assert app.bool_from_env("off", True) is False


def test_int_from_env_defaults_when_missing_or_invalid():
    assert app.int_from_env(None, 514) == 514
    assert app.int_from_env("not-an-int", 514) == 514


def test_int_from_env_parses_integer():
    assert app.int_from_env("1514", 514) == 1514


def test_float_from_env_defaults_when_missing_or_invalid():
    assert app.float_from_env(None, 10.0) == 10.0
    assert app.float_from_env("not-a-float", 10.0) == 10.0


def test_float_from_env_parses_float():
    assert app.float_from_env("2.5", 10.0) == 2.5


def test_redact_pii_redacts_common_values():
    text = "login user=nick@example.com phone=308-555-1212 " "ip=192.168.1.25 password=supersecret"

    result = app.redact_pii(text)

    assert result["pii_detected"] is True
    assert "nick@example.com" not in result["redacted_text"]
    assert "308-555-1212" not in result["redacted_text"]
    assert "192.168.1.25" not in result["redacted_text"]
    assert "supersecret" not in result["redacted_text"]
    assert "[REDACTED_EMAIL]" in result["redacted_text"]
    assert "[REDACTED_PHONE]" in result["redacted_text"]
    assert "[REDACTED_IP]" in result["redacted_text"]
    assert "[REDACTED_SECRET]" in result["redacted_text"]


def test_redact_authorization_header():
    result = app.redact_pii("Authorization: Bearer abcdef123456")

    assert result["pii_detected"] is True
    assert "abcdef123456" not in result["redacted_text"]
    assert "authorization: [REDACTED_SECRET]" in result["redacted_text"]


def test_redact_ssn():
    result = app.redact_pii("customer ssn=123-45-6789")

    assert result["pii_detected"] is True
    assert "123-45-6789" not in result["redacted_text"]
    assert "[REDACTED_SSN]" in result["redacted_text"]


def test_redact_mac_address():
    result = app.redact_pii("mac=aa:bb:cc:dd:ee:ff")

    assert result["pii_detected"] is True
    assert "aa:bb:cc:dd:ee:ff" not in result["redacted_text"]
    assert "[REDACTED_MAC]" in result["redacted_text"]


def test_redact_credit_card_uses_luhn_check():
    result = app.redact_pii("payment card=4111 1111 1111 1111")

    assert result["pii_detected"] is True
    assert "4111 1111 1111 1111" not in result["redacted_text"]
    assert "[REDACTED_CREDIT_CARD]" in result["redacted_text"]


def test_redact_credit_card_leaves_invalid_luhn_candidate():
    result = app.redact_pii("candidate card=4111 1111 1111 1112")

    assert "[REDACTED_CREDIT_CARD]" not in result["redacted_text"]
    assert "4111 1111 1111 1112" in result["redacted_text"]


def test_luhn_checksum_valid_card_is_zero():
    assert app.luhn_checksum("4111111111111111") == 0


def test_is_likely_credit_card_accepts_valid_number():
    assert app.is_likely_credit_card("4111 1111 1111 1111") is True


def test_is_likely_credit_card_rejects_invalid_number():
    assert app.is_likely_credit_card("4111 1111 1111 1112") is False


def test_find_stream_id_matches_title():
    streams = (
        {"id": "abc", "title": "default"},
        {"id": "def", "title": "test"},
    )

    assert app.find_stream_id("test", streams) == "def"


def test_find_stream_id_matches_name():
    streams = (
        {"id": "abc", "name": "default"},
        {"id": "def", "name": "test"},
    )

    assert app.find_stream_id("test", streams) == "def"


def test_find_stream_id_raises_when_missing():
    with pytest.raises(LookupError):
        app.find_stream_id("missing", ({"id": "abc", "title": "test"},))


def test_build_recent_messages_params():
    result = app.build_recent_messages_params(
        stream_id="stream-id",
        limit=10,
        range_seconds=60,
    )

    assert result == {
        "query": "*",
        "filter": "streams:stream-id",
        "range": 60,
        "limit": 10,
        "sort": "timestamp:desc",
    }


def test_simplify_message_extracts_expected_fields():
    wrapper = {
        "id": "wrapper-id",
        "index": "graylog_0",
        "message": {
            "_id": "message-id",
            "timestamp": "2026-05-18T12:00:00.000Z",
            "source": "server01",
            "message": "hello",
            "streams": ["stream-1"],
        },
    }

    result = app.simplify_message(wrapper)

    assert result == {
        "timestamp": "2026-05-18T12:00:00.000Z",
        "source": "server01",
        "message": "hello",
        "stream_ids": ["stream-1"],
        "index": "graylog_0",
        "id": "wrapper-id",
    }


def test_simplify_message_falls_back_to_message_id():
    wrapper = {
        "index": "graylog_0",
        "message": {
            "_id": "message-id",
            "message": "hello",
        },
    }

    result = app.simplify_message(wrapper)

    assert result["id"] == "message-id"


def test_severity_to_syslog_level():
    assert app.severity_to_syslog_level("high") == 3
    assert app.severity_to_syslog_level("medium") == 4
    assert app.severity_to_syslog_level("low") == 6
    assert app.severity_to_syslog_level("unknown") == 5
    assert app.severity_to_syslog_level("weird") == 5


def test_sanitize_syslog_value_escapes_quotes_backslashes_and_newlines():
    result = app.sanitize_syslog_value('hello "quoted" \\ path\nnext')

    assert result == 'hello \\"quoted\\" \\\\ path\\nnext'


def test_truncate_utf8_bytes_leaves_short_text_unchanged():
    assert app.truncate_utf8_bytes("hello", 100) == "hello"


def test_truncate_utf8_bytes_truncates_long_text_within_limit():
    result = app.truncate_utf8_bytes("a" * 100, 20)

    assert result.endswith("...[TRUNCATED]")
    assert len(result.encode("utf-8")) <= 20


def test_compact_json_serializes_without_spaces():
    assert app.compact_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_remove_none_values_removes_only_none():
    result = app.remove_none_values({"a": 1, "b": None, "c": False})

    assert result == {"a": 1, "c": False}


def test_build_gelf_custom_fields_contains_routing_and_context_fields():
    result = app.build_gelf_custom_fields(sample_enriched_message(), "nick-ollama-out")

    assert result["_ollama_output_stream"] == "nick-ollama-out"
    assert result["_pipeline"] == "greylog-ollama-enrichment"
    assert result["_original_greylog_id"] == "msg-1"
    assert result["_original_greylog_index"] == "graylog_0"
    assert result["_original_source"] == "server01"
    assert result["_pii_detected"] is True
    assert result["_ollama_model"] == "qwen3:1.7b"
    assert result["_likely_component"] == "sip"
    assert result["_likely_event_type"] == "auth_failure"
    assert result["_severity_hint"] == "medium"
    assert json.loads(result["_pii_findings"]) == [{"count": 1, "type": "email"}]


def test_build_gelf_payload_contains_required_and_routing_fields(monkeypatch):
    monkeypatch.setattr(app, "unix_timestamp_now", lambda: 1_716_000_000.25)

    result = app.build_gelf_payload(
        enriched_message=sample_enriched_message(),
        output_stream="nick-ollama-out",
        host="test-host",
        max_full_message_bytes=60_000,
    )

    assert result["version"] == "1.1"
    assert result["host"] == "test-host"
    assert result["short_message"] == "Test summary"
    assert result["timestamp"] == 1_716_000_000.25
    assert result["level"] == 4
    assert result["_ollama_output_stream"] == "nick-ollama-out"
    assert result["_pipeline"] == "greylog-ollama-enrichment"
    assert result["_original_greylog_id"] == "msg-1"
    assert result["_pii_detected"] is True
    assert result["_ollama_model"] == "qwen3:1.7b"
    assert json.loads(result["full_message"])["id"] == "msg-1"


def test_build_gelf_payload_truncates_full_message(monkeypatch):
    monkeypatch.setattr(app, "unix_timestamp_now", lambda: 1_716_000_000.25)
    enriched = sample_enriched_message()
    enriched["very_large_field"] = "x" * 10_000

    result = app.build_gelf_payload(
        enriched_message=enriched,
        output_stream="nick-ollama-out",
        host="test-host",
        max_full_message_bytes=200,
    )

    assert len(result["full_message"].encode("utf-8")) <= 200
    assert result["full_message"].endswith("...[TRUNCATED]")


def test_encode_gelf_tcp_frame_appends_null_byte():
    payload = {
        "version": "1.1",
        "host": "test-host",
        "short_message": "hello",
    }

    result = app.encode_gelf_tcp_frame(payload)

    assert result.endswith(b"\0")
    assert json.loads(result[:-1].decode("utf-8")) == payload


def test_send_gelf_tcp_sends_null_delimited_frame(monkeypatch):
    captured = {}

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return None

        def sendall(self, frame):
            captured["frame"] = frame

    def fake_create_tcp_connection(host, port, timeout, use_tls, insecure_tls):
        captured["host"] = host
        captured["port"] = port
        captured["timeout"] = timeout
        captured["use_tls"] = use_tls
        captured["insecure_tls"] = insecure_tls
        return FakeSocket()

    monkeypatch.setattr(app, "create_tcp_connection", fake_create_tcp_connection)

    payload = {
        "version": "1.1",
        "host": "test-host",
        "short_message": "hello",
    }

    result = app.send_gelf_tcp(
        host="sip.hamiltoncaptel.com",
        port=12201,
        payload=payload,
        timeout=5.0,
        use_tls=False,
        insecure_tls=False,
    )

    assert result["posted"] is True
    assert result["method"] == "gelf_tcp"
    assert result["host"] == "sip.hamiltoncaptel.com"
    assert result["port"] == 12201
    assert result["tls"] is False
    assert captured["frame"].endswith(b"\0")
    assert json.loads(captured["frame"][:-1].decode("utf-8")) == payload


def test_post_gelf_tcp_message_builds_and_sends(monkeypatch):
    captured = {}

    def fake_send_gelf_tcp(host, port, payload, timeout, use_tls, insecure_tls):
        captured["host"] = host
        captured["port"] = port
        captured["payload"] = payload
        captured["timeout"] = timeout
        captured["use_tls"] = use_tls
        captured["insecure_tls"] = insecure_tls
        return {
            "posted": True,
            "method": "gelf_tcp",
            "host": host,
            "port": port,
            "tls": use_tls,
            "frame_bytes": 123,
        }

    monkeypatch.setattr(app, "send_gelf_tcp", fake_send_gelf_tcp)
    monkeypatch.setattr(app, "unix_timestamp_now", lambda: 1_716_000_000.25)

    result = app.post_gelf_tcp_message(
        enriched_message=sample_enriched_message(),
        output_stream="nick-ollama-out",
        gelf_tcp_host="sip.hamiltoncaptel.com",
        gelf_tcp_port=12201,
        output_host="script-host",
        timeout=5.0,
        use_tls=False,
        insecure_tls=False,
        max_full_message_bytes=60_000,
    )

    assert result["posted"] is True
    assert result["method"] == "gelf_tcp"
    assert captured["host"] == "sip.hamiltoncaptel.com"
    assert captured["port"] == 12201
    assert captured["payload"]["host"] == "script-host"
    assert captured["payload"]["_ollama_output_stream"] == "nick-ollama-out"


def test_build_syslog_fields_contains_routing_and_context_fields():
    result = app.build_syslog_fields(sample_enriched_message(), "nick-ollama-out")

    assert result["ollama_output_stream"] == "nick-ollama-out"
    assert result["pipeline"] == "greylog-ollama-enrichment"
    assert result["original_greylog_id"] == "msg-1"
    assert result["original_greylog_index"] == "graylog_0"
    assert result["original_source"] == "server01"
    assert result["pii_detected"] is True
    assert result["ollama_model"] == "qwen3:1.7b"
    assert result["likely_component"] == "sip"
    assert result["likely_event_type"] == "auth_failure"
    assert result["severity_hint"] == "medium"


def test_build_syslog_field_text_quotes_values():
    result = app.build_syslog_field_text(
        {
            "a": "one",
            "b": "two words",
            "c": None,
        }
    )

    assert 'a="one"' in result
    assert 'b="two words"' in result
    assert "c=" not in result


def test_build_syslog_message_contains_route_marker_and_summary():
    result = app.build_syslog_message(
        enriched_message=sample_enriched_message(),
        output_stream="nick-ollama-out",
        host="test-host",
        max_bytes=60_000,
    )

    assert result.startswith("<4>1 ")
    assert " test-host greylog-ollama " in result
    assert 'ollama_output_stream="nick-ollama-out"' in result
    assert 'summary="Test summary"' in result
    assert 'enriched_json="' in result


def test_send_syslog_udp_sends_bytes(monkeypatch):
    sent = {}

    class FakeSocket:
        def __init__(self, family, sock_type):
            sent["family"] = family
            sent["sock_type"] = sock_type

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return None

        def sendto(self, payload, destination):
            sent["payload"] = payload
            sent["destination"] = destination

    monkeypatch.setattr(app.socket, "socket", FakeSocket)

    result = app.send_syslog_udp("greylog.example.com", 514, "hello")

    assert result["posted"] is True
    assert result["method"] == "syslog_udp"
    assert result["host"] == "greylog.example.com"
    assert result["port"] == 514
    assert result["bytes"] == 5
    assert sent["family"] == socket.AF_INET
    assert sent["sock_type"] == socket.SOCK_DGRAM
    assert sent["payload"] == b"hello"
    assert sent["destination"] == ("greylog.example.com", 514)


def test_maybe_post_enriched_message_skips_when_disabled():
    args = argparse.Namespace(
        post_output=False,
    )

    result = app.maybe_post_enriched_message(args, sample_enriched_message())

    assert result == {"posted": False, "reason": "disabled"}


def test_maybe_post_enriched_message_uses_gelf_tcp(monkeypatch):
    captured = {}

    def fake_post_gelf_tcp_message(
        enriched_message,
        output_stream,
        gelf_tcp_host,
        gelf_tcp_port,
        output_host,
        timeout,
        use_tls,
        insecure_tls,
        max_full_message_bytes,
    ):
        captured["enriched_message"] = enriched_message
        captured["output_stream"] = output_stream
        captured["gelf_tcp_host"] = gelf_tcp_host
        captured["gelf_tcp_port"] = gelf_tcp_port
        captured["output_host"] = output_host
        captured["timeout"] = timeout
        captured["use_tls"] = use_tls
        captured["insecure_tls"] = insecure_tls
        captured["max_full_message_bytes"] = max_full_message_bytes
        return {"posted": True, "method": "gelf_tcp"}

    monkeypatch.setattr(app, "post_gelf_tcp_message", fake_post_gelf_tcp_message)

    args = argparse.Namespace(
        post_output=True,
        output_method="gelf_tcp",
        output_stream="nick-ollama-out",
        gelf_tcp_host="sip.hamiltoncaptel.com",
        gelf_tcp_port=12201,
        output_host="script-host",
        gelf_tcp_timeout=5.0,
        gelf_tcp_tls=False,
        gelf_tcp_insecure_tls=False,
        max_gelf_full_message_bytes=60_000,
    )

    result = app.maybe_post_enriched_message(args, sample_enriched_message())

    assert result == {"posted": True, "method": "gelf_tcp"}
    assert captured["output_stream"] == "nick-ollama-out"
    assert captured["gelf_tcp_host"] == "sip.hamiltoncaptel.com"
    assert captured["gelf_tcp_port"] == 12201
    assert captured["output_host"] == "script-host"


def test_maybe_post_enriched_message_uses_syslog_udp(monkeypatch):
    captured = {}

    def fake_post_syslog_udp_message(
        enriched_message,
        output_stream,
        syslog_host,
        syslog_port,
        output_host,
        max_bytes,
    ):
        captured["enriched_message"] = enriched_message
        captured["output_stream"] = output_stream
        captured["syslog_host"] = syslog_host
        captured["syslog_port"] = syslog_port
        captured["output_host"] = output_host
        captured["max_bytes"] = max_bytes
        return {"posted": True, "method": "syslog_udp"}

    monkeypatch.setattr(app, "post_syslog_udp_message", fake_post_syslog_udp_message)

    args = argparse.Namespace(
        post_output=True,
        output_method="syslog_udp",
        output_stream="nick-ollama-out",
        syslog_host="sip.hamiltoncaptel.com",
        syslog_port=514,
        output_host="script-host",
        max_syslog_bytes=60_000,
    )

    result = app.maybe_post_enriched_message(args, sample_enriched_message())

    assert result == {"posted": True, "method": "syslog_udp"}
    assert captured["output_stream"] == "nick-ollama-out"
    assert captured["syslog_host"] == "sip.hamiltoncaptel.com"
    assert captured["syslog_port"] == 514


def test_maybe_post_enriched_message_rejects_unknown_method():
    args = argparse.Namespace(
        post_output=True,
        output_method="bad_method",
    )

    result = app.maybe_post_enriched_message(args, sample_enriched_message())

    assert result == {
        "posted": False,
        "reason": "unsupported_output_method:bad_method",
    }


def test_parse_tool_arguments_accepts_dict():
    tool_call = {
        "function": {
            "name": "redact_pii",
            "arguments": {"text": "hello"},
        }
    }

    assert app.parse_tool_arguments(tool_call) == {"text": "hello"}


def test_parse_tool_arguments_accepts_json_string():
    tool_call = {
        "function": {
            "name": "redact_pii",
            "arguments": '{"text": "hello"}',
        }
    }

    assert app.parse_tool_arguments(tool_call) == {"text": "hello"}


def test_tool_name_returns_function_name():
    tool_call = {
        "function": {
            "name": "redact_pii",
        }
    }

    assert app.tool_name(tool_call) == "redact_pii"


def test_execute_redaction_tool_executes_redaction():
    tool_call = {
        "function": {
            "name": "redact_pii",
            "arguments": {"text": "email nick@example.com"},
        }
    }

    result = app.execute_redaction_tool(tool_call, fallback_text="fallback")

    assert result["pii_detected"] is True
    assert "[REDACTED_EMAIL]" in result["redacted_text"]


def test_execute_redaction_tool_uses_fallback_text_when_missing_argument():
    tool_call = {
        "function": {
            "name": "redact_pii",
            "arguments": {},
        }
    }

    result = app.execute_redaction_tool(tool_call, fallback_text="email nick@example.com")

    assert result["pii_detected"] is True
    assert "[REDACTED_EMAIL]" in result["redacted_text"]


def test_execute_redaction_tool_rejects_unknown_tool():
    tool_call = {
        "function": {
            "name": "unknown",
            "arguments": {"text": "hello"},
        }
    }

    with pytest.raises(ValueError):
        app.execute_redaction_tool(tool_call, fallback_text="hello")


def test_build_tool_result_message():
    result = app.build_tool_result_message(
        "redact_pii",
        {"pii_detected": False, "findings": [], "redacted_text": "hello"},
    )

    assert result["role"] == "tool"
    assert result["tool_name"] == "redact_pii"
    assert json.loads(result["content"])["redacted_text"] == "hello"


def test_extract_tool_calls_returns_tuple():
    response = {
        "message": {
            "tool_calls": [
                {
                    "function": {
                        "name": "redact_pii",
                        "arguments": {"text": "hello"},
                    }
                }
            ]
        }
    }

    result = app.extract_tool_calls(response)

    assert isinstance(result, tuple)
    assert len(result) == 1
    assert result[0]["function"]["name"] == "redact_pii"


def test_call_redaction_tool_via_ollama_falls_back_when_model_does_not_call_tool(
    monkeypatch,
):
    def fake_call_ollama(**kwargs):
        return {"message": {"content": "no tool call"}}

    monkeypatch.setattr(app, "call_ollama", fake_call_ollama)

    redaction, tool_requested, messages = app.call_redaction_tool_via_ollama(
        ollama_api_base="http://127.0.0.1:11434",
        model="fake-model",
        log_text="email nick@example.com",
    )

    assert tool_requested is False
    assert redaction["pii_detected"] is True
    assert "[REDACTED_EMAIL]" in redaction["redacted_text"]
    assert messages[-1]["role"] == "tool"


def test_call_redaction_tool_via_ollama_executes_requested_tool(monkeypatch):
    def fake_call_ollama(**kwargs):
        return {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "redact_pii",
                            "arguments": {"text": "email nick@example.com"},
                        }
                    }
                ],
            }
        }

    monkeypatch.setattr(app, "call_ollama", fake_call_ollama)

    redaction, tool_requested, messages = app.call_redaction_tool_via_ollama(
        ollama_api_base="http://127.0.0.1:11434",
        model="fake-model",
        log_text="email nick@example.com",
    )

    assert tool_requested is True
    assert redaction["pii_detected"] is True
    assert "[REDACTED_EMAIL]" in redaction["redacted_text"]
    assert messages[-1]["role"] == "tool"


def test_parse_json_content_parses_message_content():
    response = {
        "message": {
            "content": '{"summary": "hello"}',
        }
    }

    assert app.parse_json_content(response) == {"summary": "hello"}


def test_parse_json_content_raises_on_empty_content():
    response = {
        "message": {
            "content": "",
        }
    }

    with pytest.raises(ValueError):
        app.parse_json_content(response)


def test_fallback_context_is_conservative():
    result = app.fallback_context("redacted text", "bad json")

    assert result["summary"] == "redacted text"
    assert result["likely_component"] == "unknown"
    assert result["likely_event_type"] == "unknown"
    assert result["severity_hint"] == "unknown"
    assert "bad json" in result["context"]
    assert result["recommended_next_steps"]


def test_enrich_context_with_ollama_returns_fallback_on_error(monkeypatch):
    def fake_call_ollama(**kwargs):
        raise RuntimeError("ollama unavailable")

    monkeypatch.setattr(app, "call_ollama", fake_call_ollama)

    result = app.enrich_context_with_ollama(
        ollama_api_base="http://127.0.0.1:11434",
        model="fake-model",
        base_messages=[],
        message={"id": "msg-1"},
        redaction={
            "pii_detected": False,
            "findings": [],
            "redacted_text": "hello",
        },
    )

    assert result["summary"] == "hello"
    assert result["severity_hint"] == "unknown"
    assert "ollama unavailable" in result["context"]


def test_build_context_messages_includes_redacted_message_not_original():
    result = app.build_context_messages(
        base_messages=[],
        message={
            "timestamp": "2026-05-18T12:00:00.000Z",
            "source": "server01",
            "index": "graylog_0",
            "id": "msg-1",
        },
        redaction={
            "pii_detected": True,
            "findings": [{"type": "email", "count": 1}],
            "redacted_text": "email [REDACTED_EMAIL]",
        },
    )

    assert len(result) == 1
    assert "email [REDACTED_EMAIL]" in result[0]["content"]
    assert "nick@example.com" not in result[0]["content"]


def test_parse_args_reads_gelf_tcp_defaults_from_environment(monkeypatch):
    monkeypatch.setenv("GRAYLOG_OUTPUT_METHOD", "gelf_tcp")
    monkeypatch.setenv("GRAYLOG_GELF_TCP_HOST", "sip.hamiltoncaptel.com")
    monkeypatch.setenv("GRAYLOG_GELF_TCP_PORT", "12201")
    monkeypatch.setenv("GRAYLOG_GELF_TCP_TIMEOUT", "2.5")
    monkeypatch.setenv("GRAYLOG_GELF_TCP_TLS", "true")
    monkeypatch.setenv("GRAYLOG_OUTPUT_STREAM", "nick-ollama-out")
    monkeypatch.setenv("MAX_GELF_FULL_MESSAGE_BYTES", "4096")

    args = app.parse_args([])

    assert args.output_method == "gelf_tcp"
    assert args.gelf_tcp_host == "sip.hamiltoncaptel.com"
    assert args.gelf_tcp_port == 12201
    assert args.gelf_tcp_timeout == 2.5
    assert args.gelf_tcp_tls is True
    assert args.output_stream == "nick-ollama-out"
    assert args.max_gelf_full_message_bytes == 4096


def test_parse_args_can_disable_gelf_tcp_tls_from_environment(monkeypatch):
    monkeypatch.setenv("GRAYLOG_GELF_TCP_TLS", "true")

    args = app.parse_args(["--no-gelf-tcp-tls"])

    assert args.gelf_tcp_tls is False


def test_parse_args_can_disable_post_output():
    args = app.parse_args(["--no-post-output"])

    assert args.post_output is False


def test_process_messages_processes_sequentially(monkeypatch):
    calls = []

    def fake_process_message(args, logger, ordinal, total, message):
        calls.append((ordinal, total, message["id"]))
        return {"id": message["id"], "postback": {"posted": True}}

    monkeypatch.setattr(app, "process_message", fake_process_message)

    args = argparse.Namespace()
    logger = app.configure_logging("ERROR")
    messages = (
        {"id": "msg-1"},
        {"id": "msg-2"},
    )

    result = app.process_messages(args, logger, messages)

    assert result == (
        {"id": "msg-1", "postback": {"posted": True}},
        {"id": "msg-2", "postback": {"posted": True}},
    )
    assert calls == [
        (1, 2, "msg-1"),
        (2, 2, "msg-2"),
    ]
