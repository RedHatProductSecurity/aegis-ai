import pytest

from pydantic_evals import Case

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestStatementText, PIIReportModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    run_evaluation,
)


class SuggestStatementCase(Case):
    def __init__(self, cve_id):
        """cve_id given as CVE-YYYY-NUM is the flaw we suggest description for."""
        super().__init__(
            name=f"suggest-statement-for-{cve_id}",
            inputs=cve_id,
            expected_output=None,
            metadata={"difficulty": "easy"},
        )


async def suggest_statement(cve_id: CVEID) -> PIIReportModel:
    """use rh_feature_agent to suggest description for the given CVE"""
    feature = SuggestStatementText(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    SuggestStatementCase("CVE-2025-0725"),
    SuggestStatementCase("CVE-2025-22097"),
    SuggestStatementCase("CVE-2025-23395"),
    SuggestStatementCase("CVE-2025-5399"),
    # TODO: add more cases
]

# evaluators
evals = common_feature_evals + [
    create_llm_judge(
        assertion_name="DoNotSuggestPatch",
        rubric="The suggested_statement field does not suggest to apply a source code patch or rebuild the software.",
    ),
    create_llm_judge(
        assertion_name="NoCodeLevelDetails",
        rubric="The suggested_statement field does not include any code-level details about the flaw.",
    ),
    create_llm_judge(
        assertion_name="NoDuplicatedInfo",
        rubric="The suggested_statement field does not duplicate the original_description field.  A brief summary to provide context is acceptable though.",
    ),
    # TODO: more evaluators
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_statement():
    """suggest_statement evaluation entry point"""
    await run_evaluation(cases, evals, suggest_statement)
