"""
Unit tests for FlawUpdater, focusing on aegis_meta updates.

Tests run in offline mode: Session (osidb_bindings.session) and CVE features
(aegis_ai.features.cve) are mocked so no OSIDB or LLM calls are made.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis_ai.data_models import CVEID
from aegis_ai.features.data_models import AegisAnswer
from aegis_ai.osidb_bot.bot import FlawUpdater
from aegis_ai.osidb_bot.suggest import METRICS_THR, update_field

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
        dt=datetime(2025, 3, 13, 12, 0, 0, tzinfo=UTC)
    )
    session.flaws.update = MagicMock()
    session.flaws.cvss_scores = MagicMock()
    session.flaws.cvss_scores.create = MagicMock()
    session.flaws.labels = MagicMock()
    session.flaws.labels.create = MagicMock()
    return session


async def _canned_exec_feature(feature, flaw_data):
    """Fake exec_feature that returns canned outputs per feature class (offline)."""
    name = feature.__class__.__name__
    cve_id = flaw_data["cve_id"]
    explanation = f"Canned explanation for {name} ({cve_id})"

    metrics = {"data_quality": 1.0, "confidence": 1.0, "tools_used": []}

    if name == "SuggestAffectedComponents":
        return SimpleNamespace(
            components=["kernel", "curl"],
            ecosystems=["upstream"],
            explanation=explanation,
            **metrics,
        )
    if name == "SuggestDescriptionText":
        return SimpleNamespace(
            suggested_title="Canned title",
            suggested_description="Canned description text.",
            explanation=explanation,
            **metrics,
        )
    if name == "SuggestCWE":
        return SimpleNamespace(
            cwe=["CWE-79"],
            explanation=explanation,
            **metrics,
        )
    if name == "SuggestImpact":
        return SimpleNamespace(
            impact="LOW",
            cvss3_score="3.7",
            cvss3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
            explanation=explanation,
            _flags=[],
            **metrics,
        )
    raise ValueError(f"Unknown feature: {name}")


@pytest.mark.asyncio
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


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_apply_suggestions_returns_true_on_success(
    mock_exec_feature,
):
    """apply_suggestions() returns True when all features produce high-quality output."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID)
    result = await updater.apply_suggestions()

    assert result is True
    assert updater.updated_fields
    session.flaws.labels.create.assert_not_called()


@pytest.mark.asyncio
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


@pytest.mark.asyncio
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

    session.flaws.labels.create.assert_not_called()


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_force_skips_validation(mock_exec_feature):
    """FlawUpdater.do() with force=True processes flaws that would fail validation."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    flaw_data["owner"] = "someone@example.com"

    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID, force=True)
    await updater.do()

    session.flaws.update.assert_called_once()


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_no_force_raises_on_ineligible(mock_exec_feature):
    """FlawUpdater.do() without force raises RuntimeError on ineligible flaw."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    flaw_data["owner"] = "someone@example.com"

    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID)
    with pytest.raises(RuntimeError, match="skipped because owner="):
        await updater.do()


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_read_only_skips_osidb_writes(mock_exec_feature):
    """FlawUpdater.do() with read_only=True runs suggestions but skips OSIDB writes."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID, read_only=True)
    await updater.do()

    assert updater.updated_fields
    session.flaws.update.assert_not_called()
    session.flaws.labels.create.assert_not_called()
    assert "processed" not in flaw_data.get("aegis_meta", {})


# --- Tests for aegis_meta when suggestions are discarded by check_metrics ---

LOW_QUALITY = METRICS_THR["data_quality"]["skip_thr"]
LOW_CONFIDENCE = METRICS_THR["confidence"]["skip_thr"]
TS = datetime(2025, 3, 13, 12, 0, 0, tzinfo=UTC)


def test_update_field_skipped_low_data_quality():
    """update_field records AI-Bot-Skipped when data_quality is at/below skip_thr."""
    flaw_data = _minimal_flaw_data()
    output = cast(
        AegisAnswer,
        SimpleNamespace(
            cwe=["CWE-79"],
            explanation="test",
            data_quality=LOW_QUALITY,
            confidence=1.0,
            tools_used=[],
        ),
    )

    changed = update_field(flaw_data, TS, "cwe_id", output, value="CWE-79")

    assert changed == set()
    assert flaw_data["cwe_id"] == ""

    entries = flaw_data["aegis_meta"]["cwe_id"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["type"] == "AI-Bot-Skipped"
    assert entry["skip_reason"] == "data_quality"
    assert str(LOW_QUALITY) in entry["skip_description"]
    assert str(METRICS_THR["data_quality"]["skip_thr"]) in entry["skip_description"]
    assert entry["data_quality"] == LOW_QUALITY
    assert entry["confidence"] == 1.0
    assert "timestamp" in entry


def test_update_field_skipped_low_confidence():
    """update_field records AI-Bot-Skipped when confidence is at/below skip_thr."""
    flaw_data = _minimal_flaw_data()
    output = cast(
        AegisAnswer,
        SimpleNamespace(
            impact="LOW",
            explanation="test",
            data_quality=1.0,
            confidence=LOW_CONFIDENCE,
            tools_used=[],
        ),
    )

    changed = update_field(flaw_data, TS, "impact", output, value="LOW")

    assert changed == set()
    assert flaw_data["impact"] == ""

    entries = flaw_data["aegis_meta"]["impact"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["type"] == "AI-Bot-Skipped"
    assert entry["skip_reason"] == "confidence"
    assert str(LOW_CONFIDENCE) in entry["skip_description"]
    assert str(METRICS_THR["confidence"]["skip_thr"]) in entry["skip_description"]


def test_update_field_skipped_both_metrics_low():
    """When both metrics fail, skip_reason reflects the last failing metric."""
    flaw_data = _minimal_flaw_data()
    output = cast(
        AegisAnswer,
        SimpleNamespace(
            title="Bad title",
            explanation="test",
            data_quality=LOW_QUALITY,
            confidence=LOW_CONFIDENCE,
            tools_used=[],
        ),
    )

    changed = update_field(flaw_data, TS, "title", output, value="Bad title")

    assert changed == set()
    assert flaw_data["title"] == ""

    entries = flaw_data["aegis_meta"]["title"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["type"] == "AI-Bot-Skipped"
    assert entry["skip_reason"] == "confidence"


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_all_skipped_records_aegis_meta(mock_exec_feature):
    """FlawUpdater records AI-Bot-Skipped entries when all features have low metrics."""

    async def _low_metrics_exec(feature, flaw_data):
        name = feature.__class__.__name__
        cve_id = flaw_data["cve_id"]
        explanation = f"Low-quality output for {name} ({cve_id})"
        metrics = {
            "data_quality": LOW_QUALITY,
            "confidence": LOW_CONFIDENCE,
            "tools_used": [],
        }

        if name == "SuggestAffectedComponents":
            return SimpleNamespace(
                components=["kernel"],
                ecosystems=[],
                explanation=explanation,
                **metrics,
            )
        if name == "SuggestDescriptionText":
            return SimpleNamespace(
                suggested_title="Bad title",
                suggested_description="Bad description.",
                explanation=explanation,
                **metrics,
            )
        if name == "SuggestCWE":
            return SimpleNamespace(cwe=["CWE-79"], explanation=explanation, **metrics)
        if name == "SuggestImpact":
            return SimpleNamespace(
                impact="LOW",
                cvss3_score="3.7",
                cvss3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                explanation=explanation,
                **metrics,
            )
        raise ValueError(f"Unknown feature: {name}")

    mock_exec_feature.side_effect = _low_metrics_exec

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID)

    result = await updater.apply_suggestions()
    assert result is False

    assert updater.updated_fields == set()

    aegis_meta = flaw_data["aegis_meta"]
    for field in ("components", "title", "cve_description", "cwe_id", "impact"):
        assert field in aegis_meta, f"aegis_meta missing skipped entry for {field!r}"
        entries = aegis_meta[field]
        assert len(entries) >= 1
        for entry in entries:
            assert entry["type"] == "AI-Bot-Skipped"
            assert "skip_reason" in entry
            assert "skip_description" in entry
            assert entry["data_quality"] == LOW_QUALITY
            assert entry["confidence"] == LOW_CONFIDENCE
            datetime.fromisoformat(entry["timestamp"])


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_read_only_no_manual_triage_label(mock_exec_feature):
    """FlawUpdater.do() with read_only=True skips manual-triage label even on failure."""
    mock_exec_feature.side_effect = AsyncMock(
        side_effect=RuntimeError("feature failed")
    )

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID, read_only=True)
    await updater.do()

    session.flaws.update.assert_not_called()
    session.flaws.labels.create.assert_not_called()


MANUAL_TRIAGE_LABEL = {
    "name": "manual-triage",
    "type": "workflow",
    "state": "NEW",
}


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_do_creates_manual_triage_label_on_all_skipped(
    mock_exec_feature,
):
    """FlawUpdater.do() creates manual-triage label when all suggestions are discarded."""

    async def _low_metrics_exec(feature, flaw_data):
        name = feature.__class__.__name__
        explanation = f"Low-quality output for {name}"
        metrics = {
            "data_quality": LOW_QUALITY,
            "confidence": LOW_CONFIDENCE,
            "tools_used": [],
        }

        if name == "SuggestAffectedComponents":
            return SimpleNamespace(
                components=["kernel"], ecosystems=[], explanation=explanation, **metrics
            )
        if name == "SuggestDescriptionText":
            return SimpleNamespace(
                suggested_title="t",
                suggested_description="d",
                explanation=explanation,
                **metrics,
            )
        if name == "SuggestCWE":
            return SimpleNamespace(cwe=["CWE-79"], explanation=explanation, **metrics)
        if name == "SuggestImpact":
            return SimpleNamespace(
                impact="LOW",
                cvss3_score="3.7",
                cvss3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                explanation=explanation,
                **metrics,
            )
        raise ValueError(f"Unknown feature: {name}")

    mock_exec_feature.side_effect = _low_metrics_exec

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID)
    await updater.do()

    session.flaws.labels.create.assert_called_once_with(
        flaw_id=flaw_data["uuid"],
        form_data=MANUAL_TRIAGE_LABEL,
    )


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_do_creates_manual_triage_label_on_partial_failure(
    mock_exec_feature,
):
    """FlawUpdater.do() creates manual-triage label when some features fail mid-run."""

    async def _partial_failure_exec(feature, flaw_data):
        name = feature.__class__.__name__
        if name == "SuggestCWE":
            raise RuntimeError("CWE feature crashed")
        return await _canned_exec_feature(feature, flaw_data)

    mock_exec_feature.side_effect = _partial_failure_exec

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID)
    await updater.do()

    assert updater.updated_fields
    assert "cwe_id" not in updater.updated_fields
    assert flaw_data["aegis_meta"].get("processed") is True

    session.flaws.labels.create.assert_called_once_with(
        flaw_id=flaw_data["uuid"],
        form_data=MANUAL_TRIAGE_LABEL,
    )


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_flaw_updater_do_creates_manual_triage_label_on_save_failure(
    mock_exec_feature,
):
    """FlawUpdater.do() creates manual-triage label when flaw save fails."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    session.flaws.update.side_effect = RuntimeError("OSIDB write failed")
    agent = MagicMock()

    updater = FlawUpdater(session, agent, CVE_ID)
    await updater.do()

    session.flaws.labels.create.assert_called_once_with(
        flaw_id=flaw_data["uuid"],
        form_data=MANUAL_TRIAGE_LABEL,
    )


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_schedule_retry_creates_manual_triage_on_last_attempt(mock_exec_feature):
    """process_cve() creates manual-triage label when the last retry attempt fails."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    session = _mock_session(flaw_data)
    session.flaws.update.side_effect = RuntimeError("OSIDB write failed")
    agent = MagicMock()

    from aegis_ai.osidb_bot.bot import Bot
    from aegis_ai.osidb_bot.state import BotStateFileHandler

    with (
        BotStateFileHandler(None) as sfh,
        patch(
            "aegis_ai.osidb_bot.bot.osidb_bindings.new_session", return_value=session
        ),
    ):
        bot = Bot(sfh, agent, max_retries=1)
        bot.retrying_failed = True
        bot.retry_list[CVE_ID] = 1

        await bot.process_cve(CVE_ID)

    session.flaws.labels.create.assert_called_with(
        flaw_id=flaw_data["uuid"],
        form_data=MANUAL_TRIAGE_LABEL,
    )
    assert CVE_ID not in bot.retry_list


@pytest.mark.asyncio
@patch("aegis_ai.osidb_bot.suggest.exec_feature", new_callable=AsyncMock)
async def test_validation_failure_skips_retry_and_manual_triage(mock_exec_feature):
    """process_cve() does not retry or label manual-triage for ineligible flaws."""
    mock_exec_feature.side_effect = _canned_exec_feature

    flaw_data = _minimal_flaw_data()
    flaw_data["owner"] = "someone@example.com"
    session = _mock_session(flaw_data)
    agent = MagicMock()

    from aegis_ai.osidb_bot.bot import Bot
    from aegis_ai.osidb_bot.state import BotStateFileHandler

    with (
        BotStateFileHandler(None) as sfh,
        patch(
            "aegis_ai.osidb_bot.bot.osidb_bindings.new_session", return_value=session
        ),
    ):
        bot = Bot(sfh, agent, max_retries=3)
        await bot.process_cve(CVE_ID)

    assert CVE_ID not in bot.retry_list
    session.flaws.labels.create.assert_not_called()
