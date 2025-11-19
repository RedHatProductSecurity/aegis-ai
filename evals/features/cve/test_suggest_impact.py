import cvss
import pytest

from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestImpact, SuggestImpactModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    make_eval_reason,
    run_evaluation,
)


# dict to convert "IMPORTANT" to 8.0 etc
# the following line is needed for ruff to accept the aligned comments
# fmt: off
NUM_BY_IMPACT = {
    "NONE": 0.0,        # 0
    "LOW": 2.0,         # 0..4
    "MODERATE": 5.5,    # 4..7
    "IMPORTANT": 8.0,   # 7..9
    "CRITICAL": 9.5,    # 9..10
}
# fmt: on


class SuggestImpactCase(Case):
    def __init__(self, cve_id, impact, cvss3_score):
        """cve_id given as CVE-YYYY-NUM is the flaw we query Impact for.
        impact is the expected impact as string. cvss3_score is the expected
        score specified as float."""
        super().__init__(
            name=f"suggest-impact-for-{cve_id}",
            inputs=cve_id,
            expected_output={"impact": impact, "cvss3_score": cvss3_score},
            metadata={"difficulty": "easy"},
        )


class CVSSValidator(Evaluator[str, SuggestImpactModel]):
    async def evaluate(self, ctx) -> EvaluationReason:
        """verify that cvss3_score and cvss3_vector are consistent"""
        try:
            # parse cvss3_score as float
            cvss3_score = float(ctx.output.cvss3_score)
        except Exception:
            return make_eval_reason(
                fail_reason=f"failed to parse cvss3_score: {ctx.output.cvss3_score}"
            )

        try:
            # parse cvss3_vector and compute the CVSS 3.1 score from it
            cvss3_vector = ctx.output.cvss3_vector
            cvss3_score_by_vector = cvss.CVSS3(cvss3_vector).scores()[0]
        except Exception:
            return make_eval_reason(
                fail_reason=f"failed to parse cvss3_vector: {cvss3_vector}"
            )

        if cvss3_score != cvss3_score_by_vector:
            return make_eval_reason(
                fail_reason=f"suggested cvss3_score ({cvss3_score}) does not match suggested cvss3_vector ({cvss3_score_by_vector} {cvss3_vector})"
            )

        # no problem detected
        return EvaluationReason(True)


class SuggestImpactEvaluator(Evaluator[str, SuggestImpactModel]):
    def evaluate(self, ctx: EvaluatorContext[str, SuggestImpactModel]) -> float:
        """return score based on actual and expected results"""
        # compare actual and expected impact
        imp = NUM_BY_IMPACT[ctx.output.impact]
        imp_exp = NUM_BY_IMPACT[ctx.expected_output["impact"]]  # type: ignore
        score = 1.0 - abs(imp - imp_exp) / 10.0

        try:
            # compare actual and expected cvss3_score
            cvss3 = float(ctx.output.cvss3_score)
            cvss3_exp = ctx.expected_output["cvss3_score"]  # type: ignore
            score *= 1.0 - abs(cvss3 - cvss3_exp) / 10.0
        except ValueError:
            # the provided cvss3_score field is not a number
            score -= 1.0

        conf_diff = ctx.output.confidence - score
        if 0.0 < conf_diff:
            # penalize confident models providing (partially) wrong results
            score -= conf_diff
        else:
            # negligibly penalize models providing correct results but low confidence
            score += conf_diff / 4.0

        return score


async def suggest_impact(cve_id: CVEID) -> SuggestImpactModel:
    """use rh_feature_agent to suggest Impact for the given CVE"""
    feature = SuggestImpact(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    SuggestImpactCase("CVE-2022-48701", "MODERATE", 4.9),
    SuggestImpactCase("CVE-2023-39326", "MODERATE", 7.5),
    SuggestImpactCase("CVE-2023-53693", "MODERATE", 5.5),
    SuggestImpactCase("CVE-2024-53232", "MODERATE", 4.4),
    SuggestImpactCase("CVE-2025-5399", "MODERATE", 4.3),
    SuggestImpactCase("CVE-2025-9573", "IMPORTANT", 7.2),
    SuggestImpactCase("CVE-2025-12735", "CRITICAL", 9.8),
    SuggestImpactCase("CVE-2025-23395", "MODERATE", 6.8),
    SuggestImpactCase("CVE-2025-59840", "IMPORTANT", 8.1),
]

# evaluators
evals = common_feature_evals + [
    CVSSValidator(),
    SuggestImpactEvaluator(),
    create_llm_judge(
        assertion_name="NoAffectsInExplanation",
        rubric="The 'explanation' output field does not list affected Red Hat products.  Red Hat is not a product.",
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_impact():
    """suggest_impact evaluation entry point"""
    await run_evaluation(cases, evals, suggest_impact)
