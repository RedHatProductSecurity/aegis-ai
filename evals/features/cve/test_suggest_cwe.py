import pytest
import re

from pydantic_evals import Case, Dataset
from pydantic_evals.evaluators import Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestCWE, SuggestCWEModel

from evals.features.common import common_feature_evals, handle_eval_report


# penalize models providing correct results but low confidence (the difference
# between score and confidence is divided by this number and subtracted from
# the final score)
LOW_CONFIDENCE_PENALTY_DIVISOR = 4.0


class SuggestCweCase(Case):
    def __init__(self, cve_id, cwe_list):
        """cve_id given as CVE-YYYY-NUM is the flaw we query CWE for.  cwe_list
        is the list of acceptable CWEs, the most preferred one comes first"""
        super().__init__(
            name=f"suggest-cwe-for-{cve_id}",
            inputs=cve_id,
            expected_output=cwe_list,
            metadata={"difficulty": "easy"},
        )


class SuggestCweEvaluator(Evaluator[str, SuggestCWEModel]):
    @staticmethod
    def _base_score(cwe_list_out, cwe_list_exp):
        score = 1.0
        for cwe_exp in cwe_list_exp:
            for cwe in cwe_list_out:
                # if we get "CWE-416: Use After Free", ignore the part starting with colon
                cwe_only = re.sub(r"^(CWE-[0-9]+): .*$", "\\1", cwe)
                if cwe_only == cwe_exp:
                    return score
                score *= 0.9
            score *= 0.9

        # no match
        return 0.0

    def evaluate(self, ctx: EvaluatorContext[str, SuggestCWEModel]) -> float:
        """return score based on actual and expected results"""
        cwe_list_out = ctx.output.cwe
        score = self._base_score(cwe_list_out, ctx.expected_output)

        # check how many CWEs were suggested and how man CWEs are accepted
        len_diff = len(cwe_list_out) - len(ctx.expected_output)  # type: ignore
        if 0 < len_diff:
            # penalize too many suggested CWEs for a CVE
            score *= 0.9**len_diff

        conf_diff = ctx.output.confidence - score
        if 0.0 < conf_diff:
            # penalize confident models providing (partially) wrong results
            score -= conf_diff
        else:
            # negligibly penalize models providing correct results but low confidence
            score += conf_diff / LOW_CONFIDENCE_PENALTY_DIVISOR

        return score


async def suggest_cwe(cve_id: CVEID) -> SuggestCWEModel:
    """use rh_feature_agent to suggest CWE(s) for the given CVE"""
    feature = SuggestCWE(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    SuggestCweCase("CVE-2022-48701", ["CWE-125", "CWE-20"]),
    SuggestCweCase("CVE-2024-53232", ["CWE-476", "CWE-416", "CWE-825"]),
    # CWE-269 is discouraged by MITRE and unavailable in OSIM
    # CWE-273 and CWE-73 are incorrect: https://github.com/RedHatProductSecurity/aegis/issues/71
    SuggestCweCase("CVE-2025-23395", ["CWE-271", "CWE-250", "CWE-272", "CWE-273"]),
    SuggestCweCase("CVE-2025-5399", ["CWE-835", "CWE-400"]),
    # TODO: add more cases
]

# evaluators
evals = common_feature_evals + [
    SuggestCweEvaluator(),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_cwe():
    """suggest_cwe evaluation entry point"""
    dataset = Dataset(cases=cases, evaluators=evals)
    report = await dataset.evaluate(suggest_cwe)
    handle_eval_report(report)
