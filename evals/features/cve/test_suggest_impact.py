import pytest

from pydantic_evals import Case, Dataset
from pydantic_evals.evaluators import Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestImpact, SuggestImpactModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    handle_eval_report,
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
    SuggestImpactCase("CVE-2024-53232", "MODERATE", 4.4),
    SuggestImpactCase("CVE-2025-23395", "MODERATE", 6.8),
    SuggestImpactCase("CVE-2025-5399", "MODERATE", 4.3),
    # TODO: add more cases
]

# evaluators
evals = common_feature_evals + [
    SuggestImpactEvaluator(),
    create_llm_judge(
        rubric="The 'explanation' output field does not list affected Red Hat products.  Ignore other fields in the output."
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_impact():
    """suggest_impact evaluation entry point"""
    dataset = Dataset(cases=cases, evaluators=evals)
    report = await dataset.evaluate(suggest_impact)
    handle_eval_report(report)
