"""Unit tests for severity reconciliation and post-processing.

Covers the LLM self-consistency reconciliation path and
score-to-impact band alignment.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from aegis_ai import get_settings
from aegis_ai.features.cve import SuggestImpact
from aegis_ai.features.cve.data_models import (
    RevisedExplanationModel,
    SuggestImpactModel,
)

# Shorthand CVSS vectors used across tests.
_VEC_BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
_VEC_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
_STEERING_NOTES = (
    "  Internal: privilégier le déclencheur local — 確認\n\tReproduction verified.  "
)


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


def _public_impact_result():
    initial = MagicMock()
    initial.output = SuggestImpactModel(
        cve_id="CVE-2025-1234",
        title="Public title",
        explanation="Original public explanation without internal context.",
        impact="IMPORTANT",
        cvss3_score="7.5",
        cvss3_vector=_VEC_BASE,
        data_quality=0.8,
        confidence=0.8,
        disclaimer=(
            "This response was generated by Aegis AI "
            "(https://github.com/RedHatProductSecurity/aegis-ai) "
            "using generative AI for informational purposes. "
            "All findings should be validated by a human expert."
        ),
    )
    initial.all_messages.return_value = []
    initial._state.usage.input_tokens = 0
    return initial


@pytest.fixture
def impact_revision_agent(monkeypatch):
    monkeypatch.setattr(get_settings(), "safety_enabled", False)
    revision = SimpleNamespace(
        output=RevisedExplanationModel(explanation="Revised metric rationale.")
    )
    agent = MagicMock()
    agent.name = "PublicFeatureAgent"
    agent.run = AsyncMock(side_effect=[_public_impact_result(), revision])

    def adjust_vector(output, call_str):
        # Force the vector-change branch; revision triggering is not under test.
        output.cvss3_vector = _VEC_LOCAL
        output.cvss3_score = "5.5"
        output.impact = "MODERATE"
        return "Local attack vector correction"

    monkeypatch.setattr(SuggestImpact, "post_process", staticmethod(adjust_vector))
    return agent


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cvss_context",
    [{}, {"cvss_scores": None}, {"cvss_scores": []}],
    ids=["scores-absent", "scores-null", "scores-present"],
)
@pytest.mark.parametrize(
    "notes_context, expected_revision_notes",
    [
        pytest.param({}, "", id="notes-absent"),
        pytest.param({"steering_notes": None}, "", id="notes-null"),
        pytest.param(
            {"steering_notes": ""},
            "\nInternal analyst steering notes: ",
            id="notes-empty",
        ),
        pytest.param(
            {"steering_notes": " \t\n "},
            "\nInternal analyst steering notes:  \t\n ",
            id="notes-whitespace-only",
        ),
        pytest.param(
            {"steering_notes": _STEERING_NOTES},
            f"\nInternal analyst steering notes: {_STEERING_NOTES}",
            id="notes-unicode-multiline",
        ),
    ],
)
async def test_explanation_revision_retains_request_steering_notes(
    impact_revision_agent, cvss_context, notes_context, expected_revision_notes
):
    """Revision needs request context even when it is insufficient for OSIDB deps."""
    result = await SuggestImpact(impact_revision_agent).exec(
        "CVE-2025-1234",
        static_context={
            "title": "Public title",
            "comment_zero": "Public description.",
            "components": ["curl"],
            **notes_context,
            **cvss_context,
        },
    )

    assert impact_revision_agent.run.await_count == 2
    initial_prompt, revision_call = impact_revision_agent.run.await_args_list
    initial_context = (
        initial_prompt.args[0]
        .partition("\n\nContext:\n")[2]
        .partition("\n\nFormat:")[0]
    )
    notes = notes_context.get("steering_notes")
    if notes is None:
        assert "steering_notes=" not in initial_context
    else:
        assert f"steering_notes={notes!r}" in initial_context
    assert revision_call.kwargs["output_type"] is RevisedExplanationModel
    revision_context = (
        revision_call.args[0]
        .partition("\n\nCVE context:\n")[2]
        .partition("\n\nPost-processing")[0]
    )
    assert revision_context == (
        "Title: Public title\nComponents: curl\nDescription: Public description."
        + expected_revision_notes
    )
    assert result.output._explanation_revised is True
    assert result.output.explanation.startswith("Revised metric rationale.")
    assert result.output.cvss3_vector == _VEC_LOCAL
