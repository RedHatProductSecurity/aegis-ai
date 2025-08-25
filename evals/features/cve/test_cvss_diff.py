import pytest

from pydantic_evals import Case, Dataset
from pydantic_evals.evaluators import EvaluationReason, Evaluator

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID, is_cvss_valid
from aegis_ai.features.cve import CVSSDiffExplainer, CVSSDiffExplainerModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    handle_eval_report,
    make_eval_reason,
)


class CVSSDiffCase(Case):
    def __init__(self, cve_id, has_diff):
        """cve_id given as CVE-YYYY-NUM is the flaw we rewrite description for."""
        super().__init__(
            name=f"cvss-diff-for-{cve_id}",
            inputs=cve_id,
            expected_output=has_diff,
            metadata={"difficulty": "easy"},
        )


class CVSSDiffEvaluator(Evaluator[str, CVSSDiffExplainerModel]):
    async def evaluate(self, ctx) -> EvaluationReason:
        """check that explanation is provided if and only if CVSS scores differ"""
        rh_cvss = ctx.output.redhat_cvss3_vector
        if not is_cvss_valid(rh_cvss):
            return make_eval_reason(
                fail_reason=f"invalid RH CVSS vector returned by the agent: {rh_cvss}"
            )

        nvd_cvss = ctx.output.nvd_cvss3_vector
        if not is_cvss_valid(nvd_cvss):
            return make_eval_reason(
                fail_reason=f"invalid NVD CVSS vector returned by the agent: {nvd_cvss}"
            )

        empty_explanation = len(ctx.output.explanation) == 0
        cvss_differ = rh_cvss == nvd_cvss
        return make_eval_reason(
            empty_explanation == cvss_differ,
            fail_reason="explanation emptiness does not match CVSS difference",
        )


async def cvss_diff(cve_id: CVEID) -> CVSSDiffExplainerModel:
    """use rh_feature_agent to rewrite description for the given CVE"""
    feature = CVSSDiffExplainer(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    CVSSDiffCase("CVE-2025-47229", False),
    CVSSDiffCase("CVE-2022-48701", True),
    CVSSDiffCase("CVE-2024-53232", True),
    # TODO: add more cases
]

# evaluators
evals = common_feature_evals + [
    CVSSDiffEvaluator(),
    create_llm_judge(
        rubric="Either the explanation field is an empty string or it elaborates on the reason why Red Hat assigned a different CVSS vector."
    ),
    # TODO: more evaluators
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_cvss_diff():
    """cvss_diff evaluation entry point"""
    dataset = Dataset(cases=cases, evaluators=evals)
    report = await dataset.evaluate(cvss_diff)
    handle_eval_report(report)
