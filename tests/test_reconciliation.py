"""Unit tests for severity reconciliation and post-processing.

Covers the LLM self-consistency reconciliation path and
score-to-impact band alignment.
"""

from types import SimpleNamespace

from aegis_ai.features.cve import SuggestImpact

# Shorthand CVSS vectors used across tests.
_VEC_BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
_VEC_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"


def _output(impact="MODERATE", cvss_score="5.5", cvss_vector=_VEC_BASE):
    return SimpleNamespace(
        impact=impact,
        cvss3_score=cvss_score,
        cvss3_vector=cvss_vector,
    )


# ── LLM self-consistency reconciliation ────────────────────────────


class TestReconcileSeverity:
    def test_consistent_llm_no_change(self):
        """When LLM CVSS band matches stated impact, output is unchanged."""
        out = _output(impact="MODERATE", cvss_score="5.5")
        trace = SuggestImpact.reconcile_severity(out, "t")
        assert out.impact == "MODERATE"
        assert "consistent=true" in trace

    def test_inconsistent_llm_trusts_cvss_band(self):
        """When LLM CVSS band disagrees with stated impact, CVSS band wins."""
        out = _output(impact="LOW", cvss_score="7.5")
        trace = SuggestImpact.reconcile_severity(out, "t")
        assert out.impact == "IMPORTANT"
        assert "consistent=false" in trace

    def test_important_consistent(self):
        out = _output(impact="IMPORTANT", cvss_score="7.8")
        trace = SuggestImpact.reconcile_severity(out, "t")
        assert out.impact == "IMPORTANT"
        assert "consistent=true" in trace

    def test_low_consistent(self):
        out = _output(impact="LOW", cvss_score="3.0")
        trace = SuggestImpact.reconcile_severity(out, "t")
        assert out.impact == "LOW"
        assert "consistent=true" in trace

    def test_nan_cvss_returns_empty_trace(self):
        out = _output(impact="MODERATE", cvss_score="not_a_number")
        trace = SuggestImpact.reconcile_severity(out, "t")
        assert trace == ""
        assert out.impact == "MODERATE"


# ── Score-to-impact band alignment ───────────────────────────────────


class TestAlignScoreToImpact:
    """align_score_to_impact bumps the CVSS score to the band floor when
    reconciliation moved impact above the score's natural band."""

    def test_bumps_score_moderate_to_important(self):
        out = SimpleNamespace(impact="IMPORTANT", cvss3_score="5.5")
        SuggestImpact.align_score_to_impact(out, "t")
        assert float(out.cvss3_score) == 7.1

    def test_bumps_score_low_to_moderate(self):
        out = SimpleNamespace(impact="MODERATE", cvss3_score="2.3")
        SuggestImpact.align_score_to_impact(out, "t")
        assert float(out.cvss3_score) == 4.0

    def test_bumps_score_low_to_important(self):
        out = SimpleNamespace(impact="IMPORTANT", cvss3_score="3.5")
        SuggestImpact.align_score_to_impact(out, "t")
        assert float(out.cvss3_score) == 7.1

    def test_bumps_score_to_critical(self):
        out = SimpleNamespace(impact="CRITICAL", cvss3_score="8.0")
        SuggestImpact.align_score_to_impact(out, "t")
        assert float(out.cvss3_score) == 9.1

    def test_no_change_when_already_in_band(self):
        out = SimpleNamespace(impact="MODERATE", cvss3_score="5.5")
        SuggestImpact.align_score_to_impact(out, "t")
        assert out.cvss3_score == "5.5"

    def test_no_change_when_impact_less_severe(self):
        out = SimpleNamespace(impact="LOW", cvss3_score="5.5")
        SuggestImpact.align_score_to_impact(out, "t")
        assert out.cvss3_score == "5.5"

    def test_invalid_score_no_crash(self):
        out = SimpleNamespace(impact="MODERATE", cvss3_score="bad")
        SuggestImpact.align_score_to_impact(out, "t")
        assert out.cvss3_score == "bad"


# ── Post-processing integration ───────────────────────────────────


class TestPostProcess:
    def test_consistent_no_change(self):
        """Consistent LLM output — nothing changes."""
        out = _output(impact="MODERATE", cvss_score="5.5", cvss_vector=_VEC_LOCAL)
        SuggestImpact.post_process(out, "t")
        assert out.impact == "MODERATE"
        assert out.cvss3_score == "5.5"

    def test_inconsistent_llm_fixed_by_reconciliation(self):
        """LLM says LOW but CVSS band is MODERATE → reconciliation fixes it."""
        out = _output(impact="LOW", cvss_score="5.5", cvss_vector=_VEC_LOCAL)
        SuggestImpact.post_process(out, "t")
        assert out.impact == "MODERATE"
        assert out.cvss3_score == "5.5"

    def test_score_bumped_after_reconciliation(self):
        """When reconciliation escalates impact, score is bumped to band floor."""
        out = _output(impact="LOW", cvss_score="7.5", cvss_vector=_VEC_BASE)
        SuggestImpact.post_process(out, "t")
        assert out.impact == "IMPORTANT"
        assert out.cvss3_score == "7.5"
