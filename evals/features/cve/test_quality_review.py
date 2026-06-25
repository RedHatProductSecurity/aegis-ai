import pytest

from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import QualityReview, QualityReviewModel
from aegis_ai.features.cve.data_models import (
    CATEGORY_WEIGHTS,
    RATING_EXCELLENT,
    RATING_FAILS_STANDARDS,
    RATING_GOOD,
    RATING_NEEDS_IMPROVEMENT,
)

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    make_eval_reason,
    reflect_confidence,
    run_evaluation,
)
from evals.utils.osidb_cache import read_cache_json


class QualityReviewCase(Case):
    def __init__(self, cve_id, expected_score=0.5, **kwargs):
        """cve_id is the flaw to review; expected_score is the target
        overall_score (0.0-1.0) for this CVE's content quality."""
        metadata = {"difficulty": "medium", **kwargs.pop("metadata", {})}
        super().__init__(
            name=f"quality-review-for-{cve_id}",
            inputs=cve_id,
            expected_output=expected_score,
            metadata=metadata,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Evaluators
# ---------------------------------------------------------------------------


class RubricShapeEvaluator(Evaluator[str, QualityReviewModel]):
    """Verify the output has all 30 criteria across 6 categories with valid IDs."""

    def evaluate(self, ctx) -> EvaluationReason:
        scores = ctx.output.scores

        # Check total count
        if len(scores) != len(QualityReview._REQUIRED_CRITERIA):
            return make_eval_reason(
                fail_reason=f"Expected {len(QualityReview._REQUIRED_CRITERIA)} criteria, got {len(scores)}",
            )

        # Check all 6 categories present
        found_categories = {s["category"] for s in scores}
        expected_categories = set(CATEGORY_WEIGHTS.keys())
        if found_categories != expected_categories:
            missing = expected_categories - found_categories
            unexpected = found_categories - expected_categories
            return make_eval_reason(
                fail_reason=f"Category mismatch. Missing: {missing}, Unexpected: {unexpected}",
            )

        # Check all criterion IDs match the required set
        found_criteria = {s["criterion_id"] for s in scores}
        if found_criteria != QualityReview._REQUIRED_CRITERIA:
            missing = QualityReview._REQUIRED_CRITERIA - found_criteria
            unexpected = found_criteria - QualityReview._REQUIRED_CRITERIA
            return make_eval_reason(
                fail_reason=f"Criterion ID mismatch. Missing: {missing}, Unexpected: {unexpected}",
            )

        return make_eval_reason(True)


class ScoreBoundsEvaluator(Evaluator[str, QualityReviewModel]):
    """Verify overall_score is within 0.0-1.0 and rating aligns with thresholds."""

    def evaluate(self, ctx) -> EvaluationReason:
        score = ctx.output.overall_score
        rating = ctx.output.rating

        if not (0.0 <= score <= 1.0):
            return make_eval_reason(
                fail_reason=f"overall_score {score} out of bounds [0.0, 1.0]",
            )

        # Verify rating matches score thresholds
        if score >= 0.8:
            expected = RATING_EXCELLENT
        elif score >= 0.6:
            expected = RATING_GOOD
        elif score >= 0.4:
            expected = RATING_NEEDS_IMPROVEMENT
        else:
            expected = RATING_FAILS_STANDARDS

        if rating != expected:
            return make_eval_reason(
                fail_reason=f"Rating {rating} does not match score {score} (expected {expected})",
            )

        return make_eval_reason(True)


class QualityScoreEvaluator(Evaluator[str, QualityReviewModel]):
    """Compare actual overall_score against expected score.

    Returns a score from 0.0 (completely wrong) to 1.0 (exact match),
    following the same pattern as CVSSScoreEvaluator.
    """

    def evaluate(self, ctx) -> float:
        expected = ctx.expected_output
        actual = ctx.output.overall_score
        score = 1.0 - abs(actual - expected)
        return reflect_confidence(ctx, score)


class CustomerLensEvaluator(Evaluator[str, QualityReviewModel]):
    """Verify customer lens fields are populated."""

    def evaluate(self, ctx) -> EvaluationReason:
        if not ctx.output.customer_can_decide:
            return make_eval_reason(
                fail_reason="customer_can_decide is empty",
            )
        if not ctx.output.remains_unclear:
            return make_eval_reason(
                fail_reason="remains_unclear is empty",
            )
        if not ctx.output.manual_context_needed:
            return make_eval_reason(
                fail_reason="manual_context_needed is empty",
            )
        return make_eval_reason(True)


class MitigationRewriteRulesEvaluator(Evaluator[str, QualityReviewModel]):
    """When suggested_mitigation is present, verify it doesn't suggest updating/patching."""

    def evaluate(self, ctx) -> EvaluationReason:
        mit = ctx.output.suggested_mitigation
        if mit is None:
            # No mitigation suggested — that's fine
            return make_eval_reason(True)

        lower = mit.lower()
        violations = []
        if "update" in lower:
            violations.append("contains 'update'")
        if "upgrade" in lower:
            violations.append("contains 'upgrade'")
        # Check for prescriptive patching phrases; skip descriptive uses
        # like "unpatched" or "no patch is available"
        patch_phrases = [
            "apply the patch",
            "apply patch",
            "install the patch",
            "patching is",
            "patch the",
            "patch your",
        ]
        if any(phrase in lower for phrase in patch_phrases):
            violations.append("suggests patching")

        if violations:
            return make_eval_reason(
                fail_reason=f"suggested_mitigation violates rewrite rules: {', '.join(violations)}",
            )
        return make_eval_reason(True)


# ---------------------------------------------------------------------------
# Task function
# ---------------------------------------------------------------------------


async def quality_review(cve_id: CVEID) -> QualityReviewModel:
    """Run quality-review against the given CVE using cached OSIDB data."""
    static_context = read_cache_json(str(cve_id))
    if static_context is None:
        raise AssertionError(f"Missing/invalid OSIDB cache for {cve_id}")
    feature = QualityReview(rh_feature_agent)
    result = await feature.exec(cve_id, static_context=static_context)
    return result.output


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

cases = [
    # Rich content: statement + mitigation + detailed comment_zero
    QualityReviewCase(
        "CVE-2023-48795",
        expected_score=0.9,
        metadata={"known_to_fail_evaluators": ["MitigationRewriteRulesEvaluator"]},
    ),
    # Sparse content: no statement, short comment_zero
    QualityReviewCase(
        "CVE-2025-53020",
        expected_score=0.6,
    ),
    # Very sparse: short comment_zero, no mitigation
    QualityReviewCase(
        "CVE-2026-4724",
        expected_score=0.4,
    ),
    # Rich content: statement + mitigation + long comment_zero
    QualityReviewCase(
        "CVE-2026-22822",
        expected_score=0.9,
    ),
    # Good content: statement + mitigation
    QualityReviewCase(
        "CVE-2026-40227",
        expected_score=0.85,
    ),
]


# ---------------------------------------------------------------------------
# Evaluators
# ---------------------------------------------------------------------------

evals = common_feature_evals + [
    RubricShapeEvaluator(),
    ScoreBoundsEvaluator(),
    QualityScoreEvaluator(),
    CustomerLensEvaluator(),
    MitigationRewriteRulesEvaluator(),
    create_llm_judge(
        assertion_name="ExplanationIsRelevant",
        rubric=(
            "The 'explanation' field is not empty and it summarizes the quality "
            "review findings, mentioning specific strengths or gaps relevant to "
            "the CVE content. It should not be generic boilerplate."
        ),
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_quality_review():
    """quality_review evaluation entry point"""
    await run_evaluation(cases, evals, quality_review, agent=rh_feature_agent)
