import pytest

from pydantic_evals import Case, Dataset
from pydantic_evals.evaluators import EvaluationReason, Evaluator

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import IdentifyPII, PIIReportModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    handle_eval_report,
    make_eval_reason,
)


class IdentifyPIICase(Case):
    def __init__(self, cve_id, contains_PII):
        """cve_id given as CVE-YYYY-NUM is the flaw we rewrite description for."""
        super().__init__(
            name=f"identify-pii-for-{cve_id}",
            inputs=cve_id,
            expected_output=contains_PII,
            metadata={"difficulty": "easy"},
        )


class IdentifyPIIEvaluator(Evaluator[str, PIIReportModel]):
    async def evaluate(self, ctx) -> EvaluationReason:
        """check the contains_PII flag in the answer"""
        if ctx.output.contains_PII != ctx.expected_output:
            return make_eval_reason(
                fail_reason="wrong value of the contains_PII flag",
            )

        empty_explanation = len(ctx.output.explanation) == 0
        return make_eval_reason(
            empty_explanation != ctx.expected_output,
            fail_reason="explanation does not match the contains_PII flag",
        )


async def identify_pii(cve_id: CVEID) -> PIIReportModel:
    """use rh_feature_agent to rewrite description for the given CVE"""
    feature = IdentifyPII(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    IdentifyPIICase("CVE-2025-0725", True),
    IdentifyPIICase("CVE-2025-23395", False),
    IdentifyPIICase("CVE-2025-5399", False),
    # TODO: add more cases
]

# evaluators
evals = common_feature_evals + [
    IdentifyPIIEvaluator(),
    create_llm_judge(
        rubric="If the contains_PII field is True, the explanation field is NOT empty."
    ),
    create_llm_judge(
        rubric="Either the explanation field is empty, or it contains a bulleted list starting with '-'."
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_identify_pii():
    """identify_pii evaluation entry point"""
    dataset = Dataset(cases=cases, evaluators=evals)
    report = await dataset.evaluate(identify_pii)
    handle_eval_report(report)
