"""
Unit tests for FlawUpdater, focusing on aegis_meta updates.

Tests run in offline mode: Session (osidb_bindings.session) and CVE features
(aegis_ai.features.cve) are mocked so no OSIDB or LLM calls are made.
"""

import pytest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from aegis_ai.data_models import CVEID
from aegis_ai.osidb_bot.bot import FlawUpdater


pytestmark = pytest.mark.asyncio

CVE_ID: CVEID = "CVE-2025-0001"


def _minimal_flaw_data() -> dict:
    """Build minimal flaw_data that passes FlawFinder.validate(ELIGIBLE_FLAWS)."""
    return {
        "aegis_meta": {},
        "affects": [],
        "classification": {"workflow": "DEFAULT", "state": "NEW"},
        "comment_zero": "",
        "comments": [],
        "components": [],
        "created_dt": "2025-01-01T00:00:00Z",
        "cve_description": "",
        "cve_id": CVE_ID,
        "cvss_scores": [],
        "cwe_id": "",
        "embargoed": False,
        "impact": "",
        "mitigation": "",
        "owner": "",
        "references": [],
        "source": "CVEORG",
        "statement": "",
        "title": "",
        "updated_dt": "2025-01-01T00:00:00Z",
        "uuid": "00000000-0000-0000-0000-000000000001",
    }


def _mock_session(flaw_data: dict) -> MagicMock:
    """Create a mock Session that returns the given flaw_data and a fixed timestamp."""
    session = MagicMock()
    session.flaws.retrieve.return_value = MagicMock(to_dict=lambda: flaw_data)
    session.status.return_value = MagicMock(
        dt=datetime(2025, 3, 13, 12, 0, 0, tzinfo=timezone.utc)
    )
    session.flaws.update = MagicMock()
    session.flaws.cvss_scores = MagicMock()
    session.flaws.cvss_scores.create = MagicMock()
    return session


async def _canned_exec_feature(feature, flaw_data):
    """Fake exec_feature that returns canned outputs per feature class (offline)."""
    name = feature.__class__.__name__
    cve_id = flaw_data["cve_id"]
    explanation = f"Canned explanation for {name} ({cve_id})"

    if name == "SuggestAffectedComponents":
        return SimpleNamespace(
            components=["kernel", "curl"],
            explanation=explanation,
        )
    if name == "SuggestDescriptionText":
        return SimpleNamespace(
            suggested_title="Canned title",
            suggested_description="Canned description text.",
            explanation=explanation,
        )
    if name == "SuggestCWE":
        return SimpleNamespace(
            cwe=["CWE-79"],
            explanation=explanation,
        )
    if name == "SuggestImpact":
        return SimpleNamespace(
            impact="LOW",
            cvss3_score="3.7",
            cvss3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
            explanation=explanation,
        )
    raise ValueError(f"Unknown feature: {name}")


@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_aegis_meta_updated_by_suggestions(mock_exec_feature):
    """FlawUpdater.apply_suggestions() populates aegis_meta for each updated field."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID)
    assert updater.flaw_data is flaw_data

    await updater.apply_suggestions()

    aegis_meta = flaw_data["aegis_meta"]
    assert "aegis_meta" in flaw_data
    assert isinstance(aegis_meta, dict)

    # Each suggestion path that calls update_field() should add an entry per field
    expected_field_entries = {
        "components",
        "title",
        "cve_description",
        "cwe_id",
        "impact",
        "_cvss3_vector",
    }
    for field in expected_field_entries:
        assert field in aegis_meta, f"aegis_meta missing key {field!r}"
        entries = aegis_meta[field]
        assert isinstance(entries, list), f"aegis_meta[{field!r}] should be a list"
        assert len(entries) >= 1, (
            f"aegis_meta[{field!r}] should have at least one entry"
        )
        for entry in entries:
            assert entry.get("type") == "AI-Bot"
            assert "value" in entry
            assert "explanation" in entry
            assert "timestamp" in entry

    # cvss_scores is added to updated_fields but metadata is under _cvss3_vector
    assert "components" in updater.updated_fields
    assert "title" in updater.updated_fields
    assert "cve_description" in updater.updated_fields
    assert "cwe_id" in updater.updated_fields
    assert "impact" in updater.updated_fields
    assert "cvss_scores" in updater.updated_fields

    # No real OSIDB or feature exec should have been called (exec_feature was mocked)
    mock_exec_feature.assert_called()


@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_aegis_meta_entry_structure(mock_exec_feature):
    """Each aegis_meta entry has type, value, explanation, and timestamp."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID)
    await updater.apply_suggestions()

    # Inspect one field in detail (e.g. cwe_id)
    aegis_meta = flaw_data["aegis_meta"]
    assert "cwe_id" in aegis_meta
    entries = aegis_meta["cwe_id"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["type"] == "AI-Bot"
    assert entry["value"] == "CWE-79"
    assert "Canned explanation" in entry["explanation"]
    assert "timestamp" in entry
    # Timestamp should be ISO format (from update_field)
    datetime.fromisoformat(entry["timestamp"])


@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_do_sets_processed_in_aegis_meta(mock_exec_feature):
    """FlawUpdater.do() sets aegis_meta['processed'] = True after apply_suggestions."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID)
    await updater.do()

    aegis_meta = flaw_data["aegis_meta"]
    assert aegis_meta.get("processed") is True
