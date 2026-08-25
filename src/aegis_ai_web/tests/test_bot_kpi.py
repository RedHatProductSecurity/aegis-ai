"""Unit tests for osidb-bot KPI computation logic."""

from datetime import UTC, datetime

import pytest

from aegis_ai.features.cve.impact_mappings import score_cvss3_diff, score_impact_diff
from aegis_ai_web.src.endpoints.bot_kpi import (
    BotKPICacheEntry,
    FeatureStats,
    FlawCacheData,
    _compute_deviation,
    _extract_flaw_ids,
    _merge_feature_stats,
    _result_to_response,
    _serialize_flaw_feature,
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
        "cvss_scores": [],
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

    def test_list_order_insensitive(self):
        assert _values_equal(["kernel", "curl"], ["curl", "kernel"]) is True

    def test_none_suggested(self):
        assert _values_equal(None, "LOW") is False

    def test_none_current(self):
        assert _values_equal("LOW", None) is False

    def test_both_none(self):
        assert _values_equal(None, None) is True

    def test_type_mismatch_fallback(self):
        assert _values_equal("", None) is False


class TestImpactDistance:
    def test_same_severity_zero(self):
        assert score_impact_diff("LOW", "LOW") == 1.0

    def test_adjacent_low_moderate(self):
        assert score_impact_diff("LOW", "MODERATE") == 0.65

    def test_important_vs_critical_closer_than_important_vs_none(self):
        imp_crit = score_impact_diff("IMPORTANT", "CRITICAL")
        imp_none = score_impact_diff("IMPORTANT", "NONE")
        assert imp_crit > imp_none

    def test_case_insensitive(self):
        assert score_impact_diff("low", "LOW") == 1.0

    def test_unknown_severity_raises(self):
        with pytest.raises(KeyError):
            score_impact_diff("CRITICAL", "BOGUS")


class TestCvssDistance:
    def test_identical_vectors(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        score, reason = score_cvss3_diff(v, v)
        assert score == 1.0
        assert reason is None

    def test_different_vectors(self):
        high = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        low = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        score, reason = score_cvss3_diff(high, low)
        assert score < 1.0
        assert reason is not None

    def test_invalid_vectors_max_distance(self):
        score, _reason = score_cvss3_diff("invalid", "also-invalid")
        assert score == 0.0


class TestComputeDeviation:
    def test_impact_field(self):
        dev = _compute_deviation("impact", "LOW", "IMPORTANT")
        assert dev == round(1.0 - score_impact_diff("LOW", "IMPORTANT"), 4)

    def test_cvss_field(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        assert _compute_deviation("_cvss3_vector", v, v) == 0.0

    def test_other_field_returns_binary_mismatch(self):
        assert _compute_deviation("cwe_id", "CWE-79", "CWE-89") == 1.0

    def test_impact_unknown_severity_returns_max(self):
        assert _compute_deviation("impact", "CRITICAL", "BOGUS") == 1.0


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
        assert result["impact"].suggestions_compared == 1
        assert result["impact"].suggestion_deviation_sum == 0.0

        assert "cwe_id" in result
        assert result["cwe_id"].applied == 1
        assert result["cwe_id"].suggestions_compared == 1
        assert result["cwe_id"].suggestion_deviation_sum == 0.0

    def test_applied_but_modified(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW")],
        }
        flaw = _make_flaw(aegis_meta, impact="MODERATE")
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["impact"].applied == 1
        assert result["impact"].suggestions_compared == 1
        assert result["impact"].suggestion_deviation_sum > 0.0

    def test_modified_impact_records_suggestion_deviation(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("CRITICAL")],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW")
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["impact"].suggestion_deviation_sum > 0.0
        assert result["impact"].suggestions_compared == 1
        assert result["impact"].avg_suggestion_deviation == 0.75

    def test_kept_impact_zero_deviation(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW")],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW")
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["impact"].suggestions_compared == 1
        assert result["impact"].suggestion_deviation_sum == 0.0
        assert result["impact"].avg_suggestion_deviation == 0.0

    def test_skipped_entry(self):
        aegis_meta = {
            "processed": True,
            "cwe_id": [_make_skipped_entry(dq=0.4, conf=0.3)],
        }
        flaw = _make_flaw(aegis_meta)
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["cwe_id"].applied == 0
        assert result["cwe_id"].skipped == 1
        assert result["cwe_id"].suggestions_compared == 0

    def test_mixed_applied_and_skipped(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW", dq=0.9, conf=0.85)],
            "cwe_id": [_make_skipped_entry(dq=0.4, conf=0.3)],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW")
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["impact"].applied == 1
        assert result["impact"].suggestion_deviation_sum == 0.0
        assert result["cwe_id"].skipped == 1
        assert result["cwe_id"].applied == 0

    def test_no_entries_for_field(self):
        aegis_meta = {"processed": True}
        flaw = _make_flaw(aegis_meta)
        result = extract_flaw_kpi(aegis_meta, flaw)
        assert result == {}

    def test_ecosystems_excluded(self):
        aegis_meta = {
            "processed": True,
            "_ecosystems": [_make_bot_entry(["upstream"])],
        }
        flaw = _make_flaw(aegis_meta)
        result = extract_flaw_kpi(aegis_meta, flaw)
        assert "_ecosystems" not in result
        assert "ecosystems" not in result

    def test_cvss3_vector_tracked(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        aegis_meta = {
            "processed": True,
            "_cvss3_vector": [_make_bot_entry(vector)],
        }
        flaw = _make_flaw(
            aegis_meta,
            cvss_scores=[{"issuer": "RH", "vector": vector, "score": 7.5}],
        )
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert "cvss3_vector" in result
        assert "_cvss3_vector" not in result
        assert result["cvss3_vector"].applied == 1
        assert result["cvss3_vector"].suggestion_deviation_sum == 0.0

    def test_cvss3_vector_modified(self):
        suggested = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        current = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        aegis_meta = {
            "processed": True,
            "_cvss3_vector": [_make_bot_entry(suggested)],
        }
        flaw = _make_flaw(
            aegis_meta,
            cvss_scores=[{"issuer": "RH", "vector": current, "score": 2.0}],
        )
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["cvss3_vector"].suggestions_compared == 1
        assert result["cvss3_vector"].suggestion_deviation_sum > 0.0
        assert result["cvss3_vector"].avg_suggestion_deviation is not None
        assert result["cvss3_vector"].avg_suggestion_deviation > 0.0

    def test_cvss3_vector_no_rh_issuer(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        aegis_meta = {
            "processed": True,
            "_cvss3_vector": [_make_bot_entry(vector)],
        }
        flaw = _make_flaw(
            aegis_meta,
            cvss_scores=[{"issuer": "NVD", "vector": vector, "score": 7.5}],
        )
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["cvss3_vector"].applied == 1
        assert result["cvss3_vector"].suggestion_deviation_sum > 0.0

    def test_cvss3_vector_null_cvss_scores_does_not_raise(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        aegis_meta = {
            "processed": True,
            "_cvss3_vector": [_make_bot_entry(vector)],
        }
        flaw = _make_flaw(aegis_meta, cvss_scores=None)
        result = extract_flaw_kpi(aegis_meta, flaw)

        assert result["cvss3_vector"].applied == 1
        assert result["cvss3_vector"].suggestion_deviation_sum > 0.0

    def test_list_comparison_components(self):
        aegis_meta = {
            "processed": True,
            "components": [_make_bot_entry(["kernel", "curl"])],
        }
        flaw = _make_flaw(aegis_meta, components=["kernel", "curl"])
        result = extract_flaw_kpi(aegis_meta, flaw)
        assert result["components"].suggestion_deviation_sum == 0.0

    def test_multiple_bot_entries_compares_latest(self):
        aegis_meta = {
            "processed": True,
            "impact": [
                _make_bot_entry("LOW", dq=0.8, conf=0.9),
                _make_bot_entry("MODERATE", dq=0.6, conf=0.7),
            ],
        }
        flaw = _make_flaw(aegis_meta, impact="MODERATE")
        result = extract_flaw_kpi(aegis_meta, flaw)

        stats = result["impact"]
        assert stats.applied == 2
        assert stats.suggestions_compared == 1
        assert stats.suggestion_deviation_sum == 0.0
        assert stats.total_entries == 2
        assert stats.avg_data_quality == round((0.8 + 0.6) / 2, 2)
        assert stats.avg_confidence == round((0.9 + 0.7) / 2, 2)

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

    def test_non_numeric_data_quality_does_not_raise(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW", dq="n/a", conf=0.7)],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW")
        result = extract_flaw_kpi(aegis_meta, flaw)

        stats = result["impact"]
        assert stats.total_entries == 1
        assert stats.avg_data_quality == 0.0
        assert stats.avg_confidence == 0.7

    def test_none_confidence_does_not_raise(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW", dq=0.8, conf=None)],
        }
        flaw = _make_flaw(aegis_meta, impact="LOW")
        result = extract_flaw_kpi(aegis_meta, flaw)

        stats = result["impact"]
        assert stats.total_entries == 1
        assert stats.avg_data_quality == 0.8
        assert stats.avg_confidence is None

    def test_entries_predating_metrics_tracking_excluded_from_average(self):
        """Entries recorded before data_quality/confidence tracking existed
        have neither key at all; they must not drag the average toward 0."""
        old_entry = _make_bot_entry("LOW", dq=0.8, conf=0.9)
        del old_entry["data_quality"]
        del old_entry["confidence"]
        aegis_meta = {
            "processed": True,
            "impact": [old_entry, _make_bot_entry("MODERATE", dq=0.6, conf=0.7)],
        }
        flaw = _make_flaw(aegis_meta, impact="MODERATE")
        result = extract_flaw_kpi(aegis_meta, flaw)

        stats = result["impact"]
        assert stats.total_entries == 2
        assert stats.avg_data_quality == 0.6
        assert stats.avg_confidence == 0.7


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
        assert result.modified_counts["impact"] == 0

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
        assert result.modified_counts["impact"] == 1

    def test_multiple_flaws_aggregate_suggestion_deviation(self):
        flaw1 = _make_flaw(
            {"processed": True, "impact": [_make_bot_entry("CRITICAL")]},
            impact="LOW",
        )
        flaw2 = _make_flaw(
            {"processed": True, "impact": [_make_bot_entry("IMPORTANT")]},
            impact="MODERATE",
            cve_id="CVE-2025-0002",
        )
        result = aggregate_kpi([flaw1, flaw2])

        stats = result.features["impact"]
        assert result.modified_counts["impact"] == 2
        assert stats.suggestions_compared == 2
        assert stats.avg_suggestion_deviation == 0.5

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
        assert result.modified_counts["impact"] == 0
        assert result.modified_counts["cwe_id"] == 1
        assert result.features["title"].skipped == 1


class TestResultToResponse:
    def test_acceptance_rate_uses_evaluated_not_applied(self):
        # Two AI-Bot impact entries (a re-suggestion), the latest of which
        # matches the current value. acceptance_rate must be measured against
        # the single accept/reject decision (suggestions_compared == 1), not
        # the per-entry applied count (== 2), so a kept suggestion reads 100%.
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW"), _make_bot_entry("MODERATE")],
        }
        flaw = _make_flaw(aegis_meta, impact="MODERATE")
        response = _result_to_response(aggregate_kpi([flaw]))

        impact = response.features["impact"]
        assert impact.applied == 2
        assert impact.kept == 1
        assert impact.modified == 0
        assert impact.acceptance_rate == 100.0

    def test_acceptance_rate_zero_when_latest_modified(self):
        aegis_meta = {
            "processed": True,
            "impact": [_make_bot_entry("LOW"), _make_bot_entry("MODERATE")],
        }
        flaw = _make_flaw(aegis_meta, impact="CRITICAL")
        response = _result_to_response(aggregate_kpi([flaw]))

        impact = response.features["impact"]
        assert impact.kept == 0
        assert impact.modified == 1
        assert impact.acceptance_rate == 0.0


class TestFeatureStats:
    def test_avg_metrics_none_when_no_data(self):
        stats = FeatureStats()
        assert stats.avg_data_quality is None
        assert stats.avg_confidence is None

    def test_avg_suggestion_deviation_none_when_no_data(self):
        stats = FeatureStats()
        assert stats.avg_suggestion_deviation is None

    def test_avg_suggestion_deviation_calculation(self):
        stats = FeatureStats(suggestion_deviation_sum=6.0, suggestions_compared=3)
        assert stats.avg_suggestion_deviation == 2.0


class TestMergeFeatureStats:
    def test_sums_all_fields(self):
        target = FeatureStats(
            applied=3,
            skipped=1,
            data_quality_sum=2.7,
            data_quality_count=4,
            confidence_sum=2.4,
            confidence_count=4,
            total_entries=4,
            suggestion_deviation_sum=3.0,
            suggestions_compared=2,
        )
        source = FeatureStats(
            applied=2,
            skipped=3,
            data_quality_sum=1.8,
            data_quality_count=5,
            confidence_sum=1.5,
            confidence_count=5,
            total_entries=5,
            suggestion_deviation_sum=2.0,
            suggestions_compared=3,
        )
        _merge_feature_stats(target, source)
        assert target.applied == 5
        assert target.skipped == 4
        assert round(target.data_quality_sum, 1) == 4.5
        assert target.data_quality_count == 9
        assert round(target.confidence_sum, 1) == 3.9
        assert target.confidence_count == 9
        assert target.total_entries == 9
        assert round(target.suggestion_deviation_sum, 1) == 5.0
        assert target.suggestions_compared == 5


class TestBotKPICacheEntry:
    def test_build_and_round_trip(self):
        flaws = {
            "CVE-2025-0001": FlawCacheData(
                fields={
                    "impact": _serialize_flaw_feature(
                        FeatureStats(
                            applied=1,
                            skipped=1,
                            data_quality_sum=0.9,
                            data_quality_count=1,
                            confidence_sum=0.85,
                            confidence_count=1,
                            total_entries=2,
                            suggestion_deviation_sum=0.5,
                            suggestions_compared=1,
                        )
                    ),
                    "cwe_id": _serialize_flaw_feature(
                        FeatureStats(
                            applied=1,
                            suggestions_compared=1,
                            suggestion_deviation_sum=0.0,
                        )
                    ),
                }
            ),
        }
        cutoff = datetime(2025, 7, 1, 12, 0, 0, tzinfo=UTC)
        entry = BotKPICacheEntry.build(flaws, cutoff)
        json_str = entry.model_dump_json()
        restored = BotKPICacheEntry.model_validate_json(json_str)
        restored_result = restored.to_kpi_result()

        assert restored.cutoff == cutoff
        assert restored_result.total_flaws_processed == 1
        impact = restored_result.features["impact"]
        assert impact.applied == 1
        assert impact.skipped == 1
        assert impact.avg_data_quality == 0.9
        assert impact.avg_confidence == 0.85
        assert impact.suggestion_deviation_sum == 0.5
        assert impact.suggestions_compared == 1
        assert impact.avg_suggestion_deviation == 0.5
        assert restored_result.modified_counts["impact"] == 1
        assert restored_result.features["cwe_id"].applied == 1

    def test_build_resums_multiple_flaws_from_scratch(self):
        flaws = {
            "CVE-2025-0001": FlawCacheData(
                fields={
                    "impact": _serialize_flaw_feature(
                        FeatureStats(applied=1, suggestions_compared=1)
                    )
                }
            ),
            "CVE-2025-0002": FlawCacheData(
                fields={
                    "impact": _serialize_flaw_feature(
                        FeatureStats(
                            applied=1,
                            suggestions_compared=1,
                            suggestion_deviation_sum=0.75,
                        )
                    )
                }
            ),
        }
        entry = BotKPICacheEntry.build(flaws, datetime(2025, 7, 1, tzinfo=UTC))
        result = entry.to_kpi_result()

        assert result.total_flaws_processed == 2
        assert result.features["impact"].applied == 2
        assert result.modified_counts["impact"] == 1

    def test_overwriting_a_flaw_reflects_its_latest_scoring_not_the_sum(self):
        """Regression test for the staleness bug: re-scoring a flaw (e.g.
        after an analyst edits it again) must replace its prior
        contribution, not add another one alongside it."""
        cutoff = datetime(2025, 7, 1, tzinfo=UTC)
        original = BotKPICacheEntry.build(
            {
                "CVE-2025-0001": FlawCacheData(
                    fields={
                        "impact": _serialize_flaw_feature(
                            FeatureStats(applied=1, suggestions_compared=1)
                        )
                    }
                )
            },
            cutoff,
        )
        rescored_flaws = {
            **original.flaws,
            "CVE-2025-0001": FlawCacheData(
                fields={
                    "impact": _serialize_flaw_feature(
                        FeatureStats(
                            applied=1,
                            suggestions_compared=1,
                            suggestion_deviation_sum=0.75,
                        )
                    )
                }
            ),
        }
        rescored = BotKPICacheEntry.build(rescored_flaws, cutoff)
        result = rescored.to_kpi_result()

        assert result.total_flaws_processed == 1
        assert result.features["impact"].applied == 1
        assert result.modified_counts["impact"] == 1

    def test_old_schema_cache_fails_validation(self):
        """Cache files from before this schema (flat aggregate sums + a
        seen-IDs list, no `flaws`/`aggregate` keys) must fail validation so
        `_load_cache` treats them as absent and triggers a full refresh,
        rather than silently starting from an empty cache."""
        import json

        from pydantic import ValidationError

        old_format_json = json.dumps(
            {
                "cutoff": "2025-07-01T12:00:00Z",
                "total_flaws_processed": 10,
                "features": {
                    "impact": {
                        "applied": 5,
                        "skipped": 1,
                        "kept": 3,
                        "modified": 2,
                        "data_quality_sum": 4.5,
                        "confidence_sum": 3.8,
                        "total_entries": 6,
                    }
                },
                "flaw_ids": ["CVE-2025-0001"],
            }
        )
        with pytest.raises(ValidationError):
            BotKPICacheEntry.model_validate_json(old_format_json)

    def test_to_kpi_result_tolerates_missing_core_fields(self):
        """A truncated or corrupt per-flaw entry must not raise KeyError.

        Otherwise a single bad cache file would 500 every request until
        someone manually deletes it.
        """
        entry = BotKPICacheEntry.build(
            {"CVE-2025-0001": FlawCacheData(fields={"impact": {}})},
            cutoff=datetime(2025, 7, 1, tzinfo=UTC),
        )
        result = entry.to_kpi_result()
        stats = result.features["impact"]
        assert stats.applied == 0
        assert stats.skipped == 0
        assert stats.suggestions_compared == 0
        assert stats.suggestion_deviation_sum == 0.0
        assert stats.data_quality_sum == 0.0
        assert stats.confidence_sum == 0.0
        assert stats.total_entries == 0


class TestExtractFlawIds:
    def test_returns_processed_flaw_ids(self):
        flaws = [
            _make_flaw({"processed": True}, cve_id="CVE-2025-0001"),
            _make_flaw({"processed": True}, cve_id="CVE-2025-0002"),
        ]
        assert _extract_flaw_ids(flaws) == ["CVE-2025-0001", "CVE-2025-0002"]

    def test_skips_unprocessed_flaws(self):
        flaws = [
            _make_flaw({"processed": True}, cve_id="CVE-2025-0001"),
            _make_flaw({"impact": [_make_bot_entry("LOW")]}, cve_id="CVE-2025-0002"),
        ]
        assert _extract_flaw_ids(flaws) == ["CVE-2025-0001"]

    def test_skips_non_dict_aegis_meta(self):
        flaw = _make_flaw({}, cve_id="CVE-2025-0001")
        flaw["aegis_meta"] = "not a dict"
        assert _extract_flaw_ids([flaw]) == []

    def test_skips_missing_cve_id(self):
        flaw = _make_flaw({"processed": True})
        flaw.pop("cve_id")
        assert _extract_flaw_ids([flaw]) == []

    def test_empty_list(self):
        assert _extract_flaw_ids([]) == []
