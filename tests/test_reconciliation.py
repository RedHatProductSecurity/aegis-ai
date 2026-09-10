"""Unit tests for severity reconciliation and post-processing.

Covers the LLM self-consistency reconciliation path, score-to-impact
band alignment, and CVSS kpanic override.
"""

from types import SimpleNamespace

from aegis_ai.features.cve import SuggestImpact

# Shorthand CVSS vectors used across tests.
_VEC_BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
_VEC_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
_VEC_LOCAL_HHH = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


def _output(impact="MODERATE", cvss_score="5.5", cvss_vector=_VEC_BASE):
    return SimpleNamespace(
        impact=impact,
        cvss3_score=cvss_score,
        cvss3_vector=cvss_vector,
    )


def _clf(impact="MODERATE", confidence=0.8, cvss_score=7.0, features=None):
    return {
        "impact": impact,
        "confidence": confidence,
        "cvss_score": cvss_score,
        "active_features": features or [],
    }


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
    def test_non_kernel_consistent_no_change(self):
        """Non-kernel with consistent LLM output — nothing changes."""
        out = _output(impact="MODERATE", cvss_score="5.5", cvss_vector=_VEC_LOCAL)
        SuggestImpact.post_process(out, "t")
        assert out.impact == "MODERATE"
        assert out.cvss3_score == "5.5"

    def test_no_align_when_reconciliation_preserves_impact(self):
        """Classifier present but consistent — no changes."""
        out = _output(impact="MODERATE", cvss_score="5.5", cvss_vector=_VEC_LOCAL)
        SuggestImpact.post_process(out, "t", classifier_result=_clf(impact="MODERATE"))
        assert out.impact == "MODERATE"
        assert out.cvss3_score == "5.5"

    def test_inconsistent_llm_fixed_by_reconciliation(self):
        """LLM says LOW but CVSS band is MODERATE → reconciliation fixes it."""
        out = _output(impact="LOW", cvss_score="5.5", cvss_vector=_VEC_LOCAL)
        SuggestImpact.post_process(out, "t", classifier_result=_clf(impact="LOW"))
        assert out.impact == "MODERATE"
        assert out.cvss3_score == "5.5"

    def test_kpanic_override_fires_for_important(self):
        """kpanic override fires when impact is IMPORTANT, sets AC:H/S:U/A:H."""
        out = _output(
            impact="IMPORTANT",
            cvss_score="7.8",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        )
        SuggestImpact.post_process(out, "t", classifier_result=_clf(impact="IMPORTANT"))
        assert out.impact == "IMPORTANT"
        assert "AC:H" in out.cvss3_vector
        assert "S:U" in out.cvss3_vector
        assert "A:H" in out.cvss3_vector
        assert "C:H" in out.cvss3_vector
        assert "I:H" in out.cvss3_vector

    def test_kpanic_override_fires_for_kpanic_feature(self):
        """kpanic override fires when kernel_panic feature is present."""
        out = _output(impact="MODERATE", cvss_score="5.5", cvss_vector=_VEC_LOCAL)
        SuggestImpact.post_process(
            out, "t", classifier_result=_clf(features=["kernel_panic"])
        )
        assert out.impact == "MODERATE"
        assert "AC:H" in out.cvss3_vector
        assert "A:H" in out.cvss3_vector

    def test_kpanic_override_skipped_for_critical(self):
        """kpanic override does not fire for CRITICAL impact."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        out = _output(impact="CRITICAL", cvss_score="9.8", cvss_vector=vec)
        SuggestImpact.post_process(out, "t", classifier_result=_clf(impact="IMPORTANT"))
        assert out.impact == "CRITICAL"
        assert "AC:L" in out.cvss3_vector

    def test_no_classifier_no_kpanic_override(self):
        """Without classifier result, kpanic override does not fire."""
        out = _output(
            impact="IMPORTANT",
            cvss_score="7.8",
            cvss_vector=_VEC_LOCAL_HHH,
        )
        SuggestImpact.post_process(out, "t")
        assert out.impact == "IMPORTANT"
        assert "AC:L" in out.cvss3_vector
