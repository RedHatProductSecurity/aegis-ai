"""
Unit tests for ``AppSettings`` field validation.

Covers ``bot_kpi_max_refresh_seconds`` (the default captured from
``AEGIS_BOT_KPI_MAX_REFRESH_SECS``): it must be validated against the same
inclusive 1-600 range as the osidb-bot KPI endpoint's ``max_refresh_secs``
query parameter, so a bad operator default fails loudly at settings
construction instead of reaching the endpoint as the per-call OSIDB HTTP
timeout and failing every budget-less request.
"""

import os
import subprocess
import sys

import pytest
from pydantic import ValidationError

from aegis_ai import AppSettings

_CHILD_SCRIPT = """
from aegis_ai import AppSettings

try:
    settings = AppSettings(
        default_llm_host="localhost:11434",
        default_llm_model_name="llama3.2:latest",
        default_llm_provider="",
        default_llm_api_key="",
    )
except Exception as exc:
    print(f"REJECTED {type(exc).__name__}")
else:
    print(f"ACCEPTED {settings.bot_kpi_max_refresh_seconds}")
"""


def _settings(**overrides) -> AppSettings:
    """Build ``AppSettings`` with every env-derived LLM field pinned.

    ``AppSettings`` captures the ``AEGIS_*`` variables in the class body,
    i.e. once at import, so a developer who exports them would otherwise
    have them bleed into these tests. The field under test is passed
    through as an override (the approach of ``tests/test_llm_provider.py``).
    """
    return AppSettings(
        default_llm_host="localhost:11434",
        default_llm_model_name="llama3.2:latest",
        default_llm_provider="",
        default_llm_api_key="",
        **overrides,
    )


def _construct_in_fresh_interpreter(env_value: str) -> str:
    """Construct ``AppSettings`` in a fresh interpreter with the env var set.

    ``AEGIS_BOT_KPI_MAX_REFRESH_SECS`` is read into the field default when
    ``aegis_ai`` is imported, so exercising the operator-facing path (export
    the variable, start the server) requires a subprocess: setting it in
    this process cannot change the already-captured default. Other
    ``AEGIS_*`` variables are dropped from the child environment so a
    developer's exported settings cannot bleed in, and the LLM fields are
    pinned in the child for the same reason (a repository ``.env`` file is
    still loaded at import and cannot override an already-set variable).
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_")}
    env["AEGIS_BOT_KPI_MAX_REFRESH_SECS"] = env_value
    result = subprocess.run(
        [sys.executable, "-c", _CHILD_SCRIPT],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize("value", [0, -1, 601])
def test_bot_kpi_max_refresh_seconds_rejects_out_of_range(value):
    """Values outside the inclusive 1-600 range fail at settings
    construction: a zero or negative budget would otherwise reach the KPI
    endpoint as the per-call OSIDB HTTP timeout and fail every request
    that does not pass ``max_refresh_secs`` explicitly."""
    with pytest.raises(ValidationError, match="bot_kpi_max_refresh_seconds"):
        _settings(bot_kpi_max_refresh_seconds=value)


@pytest.mark.parametrize("value", [1, 20, 600])
def test_bot_kpi_max_refresh_seconds_accepts_inclusive_bounds(value):
    """The bounds are inclusive, matching the ``max_refresh_secs`` query
    parameter: 1 and 600 are valid budgets, as is the documented default
    of 20."""
    settings = _settings(bot_kpi_max_refresh_seconds=value)
    assert settings.bot_kpi_max_refresh_seconds == value


def test_env_var_default_rejected_at_construction():
    """An operator exporting ``AEGIS_BOT_KPI_MAX_REFRESH_SECS=0`` gets a
    loud settings-construction failure rather than a server whose every
    budget-less KPI request fails on a zero per-call HTTP timeout."""
    assert _construct_in_fresh_interpreter("0") == "REJECTED ValidationError"


def test_env_var_blank_keeps_documented_default():
    """A blank/whitespace-only value (common in container/orchestrator
    configs) falls back to the default of 20 seconds instead of failing
    validation."""
    assert _construct_in_fresh_interpreter("   ") == "ACCEPTED 20"
