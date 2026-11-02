"""
Unit tests for LLM provider selection.

Covers:
- `_resolve_llm_provider()` hostname sniffing (the historical behaviour)
- the `AEGIS_LLM_PROVIDER` override used to reach API gateways (EnMaaS, ...)
- which provider/base_url/api_key `AppSettings.default_llm_model` ends up with
"""

import pytest
from pydantic import ValidationError

from aegis_ai import AppSettings, _resolve_llm_provider


@pytest.fixture(autouse=True)
def clear_llm_env(monkeypatch):
    """Keep vendor SDK env vars out of the assertions.

    These are read when the provider is constructed, so clearing them here
    works. `ANTHROPIC_BASE_URL` matters in particular: the Anthropic SDK
    honours it, so a developer pointing their own tooling at a gateway would
    otherwise see the "talks to Anthropic directly" assertions fail.

    The `AEGIS_*` variables are *not* handled here -- see `_settings()`.
    """
    for name in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def _settings(
    *,
    default_llm_host: str = "localhost:11434",
    default_llm_model_name: str = "llama3.2:latest",
    default_llm_provider: str = "",
    default_llm_api_key: str = "",
) -> AppSettings:
    """Build `AppSettings` with every env-derived LLM field pinned.

    `AppSettings` captures the `AEGIS_*` variables through `os.getenv` in the
    class body, i.e. once at import. A fixture cannot undo that, so a developer
    who exports `AEGIS_LLM_PROVIDER` or `AEGIS_LLM_API_KEY` -- exactly what
    using a gateway requires -- would otherwise have them bleed into tests that
    did not set them. Pin the defaults explicitly instead of relying on the
    environment being empty.
    """
    return AppSettings(
        default_llm_host=default_llm_host,
        default_llm_model_name=default_llm_model_name,
        default_llm_provider=default_llm_provider,
        default_llm_api_key=default_llm_api_key,
    )


@pytest.mark.parametrize(
    "host,expected",
    [
        # vendor hostnames keep being recognised without any extra config
        ("https://api.anthropic.com", "anthropic"),
        ("api.anthropic.com", "anthropic"),
        ("https://generativelanguage.googleapis.com", "google"),
        # everything else is assumed to speak the OpenAI API
        ("localhost:11434", "openai"),
        ("http://localhost:11434", "openai"),
        ("https://api.enmaas.devshift.net", "openai"),
        ("", "openai"),
        # a hostname that merely *contains* a vendor domain is not that vendor
        ("https://api.anthropic.com.evil.test", "openai"),
    ],
)
def test_provider_sniffed_from_host(host, expected):
    assert _resolve_llm_provider("", host) == expected


@pytest.mark.parametrize("provider", ["openai", "anthropic", "google"])
def test_explicit_provider_overrides_host(provider):
    """An explicit provider wins even when the host looks like another vendor."""
    assert _resolve_llm_provider(provider, "https://api.anthropic.com") == provider


@pytest.mark.parametrize("provider", ["Anthropic", " openai ", "GOOGLE"])
def test_explicit_provider_is_normalised(provider):
    assert _resolve_llm_provider(provider, "") == provider.strip().lower()


def test_unsupported_provider_rejected():
    with pytest.raises(ValueError, match="unsupported AEGIS_LLM_PROVIDER"):
        _resolve_llm_provider("bedrock", "")


def test_unsupported_provider_rejected_at_settings_init():
    with pytest.raises(ValidationError, match="unsupported AEGIS_LLM_PROVIDER"):
        _settings(default_llm_provider="bedrock")


def test_openai_host_is_suffixed_with_v1():
    model = _settings(
        default_llm_host="https://api.enmaas.devshift.net",
        default_llm_model_name="rits/zai-org/glm-5-3",
        default_llm_api_key="enmaas-key",
    ).default_llm_model

    assert model.model_name == "rits/zai-org/glm-5-3"
    assert model.base_url == "https://api.enmaas.devshift.net/v1/"


def test_openai_host_trailing_slash_does_not_double_up():
    model = _settings(
        default_llm_host="https://api.enmaas.devshift.net/",
        default_llm_api_key="enmaas-key",
    ).default_llm_model

    assert model.base_url == "https://api.enmaas.devshift.net/v1/"


def test_anthropic_gateway_gets_base_url():
    """`AEGIS_LLM_PROVIDER=anthropic` points the Messages API at the gateway."""
    model = _settings(
        default_llm_host="https://api.enmaas.devshift.net",
        default_llm_provider="anthropic",
        default_llm_model_name="claude-sonnet-5",
        default_llm_api_key="enmaas-key",
    ).default_llm_model

    assert model.model_name == "claude-sonnet-5"
    assert str(model.client.base_url).rstrip("/") == "https://api.enmaas.devshift.net"


def test_anthropic_direct_keeps_sdk_default_base_url():
    """Talking to Anthropic itself must not change, gateway support or not."""
    model = _settings(
        default_llm_host="https://api.anthropic.com",
        default_llm_model_name="claude-3-5-sonnet-latest",
        default_llm_api_key="anthropic-key",
    ).default_llm_model

    assert str(model.client.base_url).rstrip("/") == "https://api.anthropic.com"


def test_google_gateway_gets_base_url():
    """A gateway token must never be sent to Google's public endpoint."""
    model = _settings(
        default_llm_host="https://api.enmaas.devshift.net",
        default_llm_provider="google",
        default_llm_model_name="gemini-3.6-flash",
        default_llm_api_key="enmaas-key",
    ).default_llm_model

    assert model.model_name == "gemini-3.6-flash"
    assert model.base_url.rstrip("/") == "https://api.enmaas.devshift.net"


def test_google_direct_keeps_sdk_default_base_url():
    model = _settings(
        default_llm_host="https://generativelanguage.googleapis.com",
        default_llm_model_name="gemini-2.5-flash",
        default_llm_api_key="google-key",
    ).default_llm_model

    assert model.base_url.rstrip("/") == "https://generativelanguage.googleapis.com"


def test_vendor_api_key_env_var_still_works(monkeypatch):
    """Without AEGIS_LLM_API_KEY each provider reads its own env var."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")

    model = _settings(default_llm_host="https://api.anthropic.com").default_llm_model

    assert model.client.api_key == "anthropic-key"


def test_aegis_llm_api_key_takes_precedence(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")

    model = _settings(
        default_llm_host="https://api.anthropic.com",
        default_llm_api_key="aegis-key",
    ).default_llm_model

    assert model.client.api_key == "aegis-key"


def test_ollama_default_is_unchanged(monkeypatch):
    """The documented zero-config Ollama setup must keep working."""
    monkeypatch.setenv("OPENAI_API_KEY", "unused-by-ollama")

    assert _settings().default_llm_model.base_url == "localhost:11434/v1/"
