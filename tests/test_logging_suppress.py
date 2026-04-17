"""Tests for logging filters in aegis_ai.config_logging."""

import logging
import sys

import pytest

from aegis_ai import SuppressThirdPartyTracebackFilter


def _record_with_exc_info(name: str) -> logging.LogRecord:
    try:
        raise ValueError("expected")
    except ValueError:
        exc_info = sys.exc_info()
    r = logging.LogRecord(
        name=name,
        level=logging.ERROR,
        pathname="p",
        lineno=1,
        msg="m",
        args=(),
        exc_info=None,
    )
    r.exc_info = exc_info
    return r


def test_suppress_traceback_filter_clears_requests_gssapi_when_not_debug():
    f = SuppressThirdPartyTracebackFilter(show_tracebacks=False)
    r = _record_with_exc_info("requests_gssapi.gssapi_")
    assert r.exc_info is not None
    assert f.filter(r) is True
    assert r.exc_info is None
    assert getattr(r, "exc_text", None) is None


def test_suppress_traceback_filter_keeps_exc_info_at_debug():
    f = SuppressThirdPartyTracebackFilter(show_tracebacks=True)
    r = _record_with_exc_info("requests_gssapi.gssapi_")
    assert f.filter(r) is True
    assert r.exc_info is not None


def test_suppress_traceback_filter_does_not_touch_aegis_loggers():
    f = SuppressThirdPartyTracebackFilter(show_tracebacks=False)
    r = _record_with_exc_info("aegis_ai.toolsets")
    assert f.filter(r) is True
    assert r.exc_info is not None


@pytest.mark.parametrize(
    "name",
    ("gssapi", "gssapi.sec_contexts"),
)
def test_suppress_traceback_filter_clears_gssapi_family(name: str):
    f = SuppressThirdPartyTracebackFilter(show_tracebacks=False)
    r = _record_with_exc_info(name)
    assert f.filter(r) is True
    assert r.exc_info is None
