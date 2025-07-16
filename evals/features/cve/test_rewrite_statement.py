import pytest

from pydantic_evals import Case, Dataset

from aegis.agents import rh_feature_agent
from aegis.features.cve import RewriteStatementText, PIIReportModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
)


class RewriteStatementCase(Case):
    def __init__(self, cve_id):
        """cve_id given as CVE-YYYY-NUM is the flaw we rewrite description for."""
        super().__init__(
            name=f"rewrite-statement-for-{cve_id}",
            inputs=cve_id,
            expected_output=None,
            metadata={"difficulty": "easy"},
        )


async def rewrite_statement(cve_id: str) -> PIIReportModel:
    """use rh_feature_agent to rewrite description for the given CVE"""
    feature = RewriteStatementText(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    RewriteStatementCase("CVE-2025-0725"),
    RewriteStatementCase("CVE-2025-23395"),
    RewriteStatementCase("CVE-2025-5399"),
    # TODO: add more cases
]

# evaluators
evals = common_feature_evals + [
    create_llm_judge(
        rubric="The statement does not suggest to apply patch or rebuild the software."
    ),
    # TODO: more evaluators
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_rewrite_statement():
    """rewrite_statement evaluation entry point"""
    dataset = Dataset(cases=cases, evaluators=evals)
    report = await dataset.evaluate(rewrite_statement)
    report.print(include_input=True, include_output=True, include_durations=False)
