"""Tests for KernelImpactClassifier._fetch_first_match."""

from unittest.mock import MagicMock

import pytest

from aegis_ai.kernel_classifier import PATCH_URL_TEMPLATES, KernelImpactClassifier


@pytest.mark.asyncio
async def test_fetch_first_match_returns_first_success(monkeypatch) -> None:
    calls = []

    async def fake_fetch_with_limit(client, url, commit_hash, size_limit, content_type):
        calls.append(url)
        if "github.com" in url:
            return "x" * 150
        raise AssertionError("should not fall through to later templates")

    monkeypatch.setattr(
        KernelImpactClassifier, "_fetch_with_limit", fake_fetch_with_limit
    )

    result = await KernelImpactClassifier._fetch_first_match(
        MagicMock(),
        "deadbeef",
        PATCH_URL_TEMPLATES,
        size_limit=1_000_000,
        min_length=100,
        content_type="patch",
    )

    assert result == "x" * 150
    assert calls == ["https://github.com/gregkh/linux/commit/deadbeef.patch"]


@pytest.mark.asyncio
async def test_fetch_first_match_falls_through_on_short_response(monkeypatch) -> None:
    attempted = []

    async def fake_fetch_with_limit(client, url, commit_hash, size_limit, content_type):
        attempted.append(url)
        if len(attempted) == 1:
            return "too short"  # below min_length, must fall through
        return "y" * 150

    monkeypatch.setattr(
        KernelImpactClassifier, "_fetch_with_limit", fake_fetch_with_limit
    )

    result = await KernelImpactClassifier._fetch_first_match(
        MagicMock(),
        "deadbeef",
        PATCH_URL_TEMPLATES,
        size_limit=1_000_000,
        min_length=100,
        content_type="patch",
    )

    assert result == "y" * 150
    assert len(attempted) == 2


@pytest.mark.asyncio
async def test_fetch_first_match_returns_none_when_all_templates_fail(
    monkeypatch,
) -> None:
    async def fake_fetch_with_limit(client, url, commit_hash, size_limit, content_type):
        return None

    monkeypatch.setattr(
        KernelImpactClassifier, "_fetch_with_limit", fake_fetch_with_limit
    )

    result = await KernelImpactClassifier._fetch_first_match(
        MagicMock(),
        "deadbeef",
        PATCH_URL_TEMPLATES,
        size_limit=1_000_000,
        min_length=100,
        content_type="patch",
    )

    assert result is None


@pytest.mark.asyncio
async def test_fetch_first_match_continues_past_exceptions(monkeypatch) -> None:
    attempted = []

    async def fake_fetch_with_limit(client, url, commit_hash, size_limit, content_type):
        attempted.append(url)
        if len(attempted) == 1:
            raise RuntimeError("connection reset")
        return "z" * 150

    monkeypatch.setattr(
        KernelImpactClassifier, "_fetch_with_limit", fake_fetch_with_limit
    )

    result = await KernelImpactClassifier._fetch_first_match(
        MagicMock(),
        "deadbeef",
        PATCH_URL_TEMPLATES,
        size_limit=1_000_000,
        min_length=100,
        content_type="patch",
    )

    assert result == "z" * 150
    assert len(attempted) == 2
