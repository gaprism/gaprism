"""Secrets must not reach log lines, whatever handler prints them."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import httpx
import pytest

from app.logging_redaction import REDACTED, install_log_redaction, redact


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "GET https://api.shodan.io/shodan/host/1.2.3.4?key=SECRET123&minify=true",
            f"GET https://api.shodan.io/shodan/host/1.2.3.4?key={REDACTED}&minify=true",
        ),
        ("token=abc123 next", f"token={REDACTED} next"),
        ("api_key: abc", f"api_key: {REDACTED}"),
        ("apikey=abc", f"apikey={REDACTED}"),
        ("API-KEY=abc", f"API-KEY={REDACTED}"),
        ("access_token=abc.def", f"access_token={REDACTED}"),
        ("secret = hunter2", f"secret = {REDACTED}"),
        ("password=hunter2;", f"password={REDACTED};"),
        ("Authorization: Bearer abc.def.ghi", f"Authorization: {REDACTED}"),
        ("authorization=Basic dXNlcjpwYXNz", f"authorization={REDACTED}"),
        (
            "could not connect to postgresql+psycopg://app:s3cr%40t@db.internal:5432/due",
            f"could not connect to postgresql+psycopg://app:{REDACTED}@db.internal:5432/due",
        ),
        ("two: key=a and token=b", f"two: key={REDACTED} and token={REDACTED}"),
    ],
)
def test_secrets_are_replaced(raw: str, expected: str) -> None:
    assert redact(raw) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        "monkey=banana",  # "key" inside a word is not a key parameter
        "keyboard=1 hotkey: x tokens=5 secretary=anna",
        "the key is under the mat",
        "https://example.com:8080/path?x=a@b",  # a port and an @ later are not credentials
        "https://user@example.com/",  # a user name without a password is not a secret
        "mailto:someone@example.com",
    ],
)
def test_ordinary_text_is_left_alone(text: str) -> None:
    assert redact(text) == text


@pytest.fixture
def captured() -> Iterator[list[logging.LogRecord]]:
    install_log_redaction()
    records: list[logging.LogRecord] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("redaction-test")
    handler = Collect()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def test_log_records_are_redacted_at_creation(captured: list[logging.LogRecord]) -> None:
    logger = logging.getLogger("redaction-test")
    logger.info("GET %s", "https://api.shodan.io/shodan/host/1.2.3.4?key=SECRET123")
    logger.info("plain %s", "message")

    redacted, plain = captured
    assert "SECRET123" not in redacted.getMessage() and f"key={REDACTED}" in redacted.getMessage()
    assert redacted.args is None  # the arguments were folded into the redacted message
    assert (plain.msg, plain.args) == ("plain %s", ("message",))  # untouched, still lazy


def test_installing_twice_wraps_the_factory_once() -> None:
    install_log_redaction()
    first = logging.getLogRecordFactory()
    install_log_redaction()
    assert logging.getLogRecordFactory() is first


def test_a_malformed_log_call_does_not_raise_into_the_caller() -> None:
    install_log_redaction()
    # Built directly: pytest's own capture handler would (deliberately) fail the test on a bad call.
    record = logging.getLogRecordFactory()(
        "redaction-test", logging.INFO, __file__, 1, "%d items", ("not a number",), None
    )
    assert (record.msg, record.args) == ("%d items", ("not a number",))  # left for the handler


def test_tracebacks_are_redacted_too(captured: list[logging.LogRecord]) -> None:
    logger = logging.getLogger("redaction-test")
    try:
        raise RuntimeError("could not connect to postgresql://app:hunter2@db/due")
    except RuntimeError:
        logger.exception("startup failed")

    (record,) = captured
    formatted = logging.Formatter("%(message)s").format(record)
    assert "hunter2" not in formatted and f"app:{REDACTED}@db" in formatted
    assert "RuntimeError" in formatted  # the traceback is still there


def test_what_httpx_logs_for_a_keyed_request_is_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    install_log_redaction()
    caplog.set_level(logging.INFO, logger="httpx")
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))) as c:
        c.get("https://api.shodan.io/shodan/host/1.2.3.4", params={"key": "SECRET-KEY-0123456789"})

    assert "api.shodan.io/shodan/host/1.2.3.4" in caplog.text  # httpx did log the request
    assert "SECRET-KEY-0123456789" not in caplog.text and f"key={REDACTED}" in caplog.text
