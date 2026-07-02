"""Unit tests for osidb-bot KPI computation logic."""

from aegis_ai.osidb_bot.kpi import (
    FeatureStats,
    _values_equal,
    aggregate_kpi,
    extract_flaw_kpi,
)


def _make_bot_entry(value, *, dq=0.9, conf=0.85):
    return {
        "type": "AI-Bot",
        "value": value,
        "explanation": "test",
        "timestamp": "2025-03-13T12:00:00",
        "data_quality": dq,
        "confidence": conf,
    }


def _make_skipped_entry(*, dq=0.4, conf=0.3):
    return {
        "type": "AI-Bot-Skipped",
        "skip_reason": "data_quality",
        "skip_description": "too low",
        "timestamp": "2025-03-13T12:00:00",
        "data_quality": dq,
        "confidence": conf,
    }


def _make_flaw(aegis_meta, **field_overrides):
    flaw = {
        "cve_id": "CVE-2025-0001",
        "components": [],
        "title": "",
        "cve_description": "",
        "cwe_id": "",
        "impact": "",
        "aegis_meta": aegis_meta,
    }
    flaw.update(field_overrides)
    return flaw


class TestValuesEqual:
    def test_same_type_equal(self):
        assert _values_equal("LOW", "LOW") is True

    def test_same_type_not_equal(self):
        assert _values_equal("LOW", "MODERATE") is False

    def test_list_equal(self):
        assert _values_equal(["kernel"], ["kernel"]) is True

    def test_list_not_equal(self):
        assert _values_equal(["kernel"], ["curl"]) is False

    def test_type_mismatch_fallback(self):
        assert _values_equal("", None) is False


class TestExtractFlawKpi:
    def test_all_applied_and_kept(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW", dq=0.9, conf=0.8)],
            "cwe_id": [_make_bot_entry("CWE-79", dq=0.85, conf=0.9)],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW", cwe_id="CWE-79")
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert "impact" in result
        assert result["impact"].applied == 1
        assert result["impact"].kept == 1
        assert result["impact"].modified == 0

        assert "cwe_id" in result
        assert result["cwe_id"].applied == 1
        assert result["cwe_id"].kept == 1

    def test_applied_but_modified(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW")],
        }
        flaw = _make_flaw(aegis_meta, impact="MODERATE")
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["impact"].applied == 1
        assert result["impact"].kept == 0
        assert result["impact"].modified == 1

    def test_skipped_entry(self):
        aegis_meta = {
            "processed": True,
            "cwe_id": [_make_skipped_entry(dq=0.4, conf=0.3)],
        }
        flaw = _make_flaw(aegis_meta)
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["cwe_id"].applied == 0
        assert result["cwe_id"].skipped == 1
        assert result["cwe_id"].kept == 0
        assert result["cwe_id"].modified == 0

    def test_mixed_applied_and_skipped(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW", dq=0.9, conf=0.85)],
            "cwe_id": [_make_skipped_entry(dq=0.4, conf=0.3)],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW")
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["impact"].applied == 1
        assert result["impact"].kept == 1
        assert result["cwe_id"].skipped == 1
        assert result["cwe_id"].applied == 0

    def test_no_entries_for_field(self):
        aegis_meta = {"processed": True}
        flaw = _make_flaw(aegis_meta)
        result = extract_flaw_kpi(aegis_meta, flaw)
        assert result == {}

    def test_underscore_fields_excluded(self):
        aegis_meta = {
            "processed": True,
            "_ecosystems": [_make_bot_entry(["upstream"])],
            "_cvss3_vector": [
                _make_bot_entry("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
            ],
        }
        flaw = _make_flaw(aegis_meta)
        result = extract_flaw_kpi(aegis_meta, flaw)
        assert "_ecosystems" not in result
        assert "_cvss3_vector" not in result

    def test_list_comparison_components(self):
        aegis_meta = {
            "processed": True,
            "components": [_make_bot_entry(["kernel", "curl"])],
        }
        flaw = _make_flaw(aegis_meta, components=["kernel", "curl"])
        result = extract_flaw_kpi(aegis_meta, flaw)
        assert result["components"].kept == 1

    def test_multiple_bot_entries_for_single_field(self):
        aegis_meta = {
            "processed": True,
            "impact": [
                _make_bot_entry("LOW", dq=0.8, conf=0.9),
                _make_bot_entry("MODERATE", dq=0.6, conf=0.7),
            ],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW")
        result = extract_flaw_kpi(aegis_meta, flaw)

        stats = result["impact"]
        assert stats.applied == 2
        assert stats.kept == 1
        assert stats.modified == 0
        assert stats.total_entries == 2
        assert stats.avg_data_quality == round((0.8 + 0.6) / 2, 2)
        assert stats.avg_confidence == round((0.9 + 0.7) / 2, 2)
        assert stats.acceptance_rate == 50.0

    def test_avg_metrics(self):
        aegis_meta = {
            "processed": True,
            "impact": [
                _make_bot_entry("LOW", dq=0.8, conf=0.7),
                _make_skipped_entry(dq=0.4, conf=0.3),
            ],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW")
        result = extract_flaw_kpi(aegis_meta, flaw)

        stats = result["impact"]
        assert stats.total_entries == 2
        assert stats.avg_data_quality == round((0.8 + 0.4) / 2, 2)
        assert stats.avg_confidence == round((0.7 + 0.3) / 2, 2)


class TestAggregateKpi:
    def test_empty_list(self):
        result = aggregate_kpi([])
        assert result.total_flaws_processed == 0
        assert result.features == {}

    def test_single_flaw(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW", dq=0.9, conf=0.8)],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW")
        result = aggregate_kpi([flaw])

        assert result.total_flaws_processed == 1
        assert result.features["impact"].applied == 1
        assert result.features["impact"].kept == 1
        assert result.features["impact"].acceptance_rate == 100.0

    def test_multiple_flaws(self):
        flaw1 = _make_flaw(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
        )
        flaw2 = _make_flaw(
            {"processed": True, "impact": [_make_bot_entry("MODERATE")]},
            impact="IMPORTANT",
            cve_id="CVE-2025-0002",
        )
        flaw3 = _make_flaw(
            {"processed": True, "impact": [_make_skipped_entry()]},
            cve_id="CVE-2025-0003",
        )
        result = aggregate_kpi([flaw1, flaw2, flaw3])

        assert result.total_flaws_processed == 3
        stats = result.features["impact"]
        assert stats.applied == 2
        assert stats.skipped == 1
        assert stats.kept == 1
        assert stats.modified == 1
        assert stats.acceptance_rate == 50.0

    def test_skips_flaw_without_processed_flag(self):
        flaw = _make_flaw(
            {"impact": [_make_bot_entry("LOW")]},
            impact="LOW",
        )
        result = aggregate_kpi([flaw])
        assert result.total_flaws_processed == 0

    def test_skips_flaw_with_invalid_aegis_meta(self):
        flaw = _make_flaw({}, impact="LOW")
        flaw["aegis_meta"] = "not a dict"
        result = aggregate_kpi([flaw])
        assert result.total_flaws_processed == 0

    def test_multiple_features(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW")],
            "cwe_id": [_make_bot_entry("CWE-79")],
            "title": [_make_skipped_entry()],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW", cwe_id="CWE-89")
        result = aggregate_kpi([flaw])

        assert result.total_flaws_processed == 1
        assert result.features["impact"].kept == 1
        assert result.features["cwe_id"].modified == 1
        assert result.features["title"].skipped == 1


class TestFeatureStats:
    def test_acceptance_rate_no_applied(self):
        stats = FeatureStats()
        assert stats.acceptance_rate == 0.0

    def test_acceptance_rate_calculation(self):
        stats = FeatureStats(applied=10, kept=7)
        assert stats.acceptance_rate == 70.0

    def test_avg_metrics_zero(self):
        stats = FeatureStats()
        assert stats.avg_data_quality == 0.0
        assert stats.avg_confidence == 0.0
