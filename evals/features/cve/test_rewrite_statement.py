import pytest

from pydantic_evals import Case, Dataset

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import RewriteStatementText, PIIReportModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    handle_eval_report,
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


async def rewrite_statement(cve_id: CVEID) -> PIIReportModel:
    """use rh_feature_agent to rewrite description for the given CVE"""
    feature = RewriteStatementText(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    RewriteStatementCase("CVE-2025-0725"),
    RewriteStatementCase("CVE-2025-22097"),
    RewriteStatementCase("CVE-2025-23395"),
    RewriteStatementCase("CVE-2025-5399"),
    # TODO: add more cases
]

# evaluators
evals = common_feature_evals + [
    create_llm_judge(
        rubric="The rewritten_statement field does not suggest to apply a source code patch or rebuild the software."
    ),
    create_llm_judge(
        rubric="The rewritten_statement field does not include any code-level details about the flaw."
    ),
    create_llm_judge(
        rubric="The rewritten_statement field does not duplicate the original_description field.  A brief summary to provide context is acceptable though."
    ),
    # TODO: more evaluators
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_rewrite_statement():
    """rewrite_statement evaluation entry point"""
    dataset = Dataset(cases=cases, evaluators=evals)
    report = await dataset.evaluate(rewrite_statement)
    handle_eval_report(report)
