import pytest
import re

from pydantic_evals import Case
from pydantic_evals.evaluators import Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestCWE, SuggestCWEModel

from evals.features.common import common_feature_evals, run_evaluation


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
# fmt: off
cases = [
    SuggestCweCase("CVE-2022-48701", ["CWE-125", "CWE-20"]),
    SuggestCweCase("CVE-2022-49885", ["CWE-190"]),
    SuggestCweCase("CVE-2023-53116", ["CWE-763"]),
    SuggestCweCase("CVE-2023-53123", ["CWE-763"]),
    SuggestCweCase("CVE-2023-53174", ["CWE-772", "CWE-459"]),
    SuggestCweCase("CVE-2024-53232", ["CWE-476", "CWE-825"]),
    SuggestCweCase("CVE-2025-5302", ["CWE-770"]),
    SuggestCweCase("CVE-2025-6547", ["CWE-347"]),
    SuggestCweCase("CVE-2025-5399", ["CWE-835", "CWE-400"]),
    SuggestCweCase("CVE-2025-9319", ["CWE-494"]),
    SuggestCweCase("CVE-2025-9390", ["CWE-120"]),
    SuggestCweCase("CVE-2025-9394", ["CWE-825"]),
    SuggestCweCase("CVE-2025-21879", ["CWE-763"]),
    SuggestCweCase("CVE-2025-22097", ["CWE-825"]),
    SuggestCweCase("CVE-2025-22115", ["CWE-413"]),
    SuggestCweCase("CVE-2025-23395", ["CWE-271", "CWE-250", "CWE-272", "CWE-273"]),
    SuggestCweCase("CVE-2025-26503", ["CWE-120"]),
    SuggestCweCase("CVE-2025-38575", ["CWE-212"]),
    SuggestCweCase("CVE-2025-38691", ["CWE-824"]),
    SuggestCweCase("CVE-2025-38695", ["CWE-476"]),
    SuggestCweCase("CVE-2025-39855", ["CWE-476"]),
    SuggestCweCase("CVE-2025-39856", ["CWE-476"]),
    SuggestCweCase("CVE-2025-39861", ["CWE-825"]),
    SuggestCweCase("CVE-2025-39864", ["CWE-763", "CWE-825"]),
    SuggestCweCase("CVE-2025-39865", ["CWE-476"]),
    SuggestCweCase("CVE-2025-39866", ["CWE-825"]),
    SuggestCweCase("CVE-2025-40779", ["CWE-617", "CWE-476"]),
    SuggestCweCase("CVE-2025-49133", ["CWE-125"]),
    SuggestCweCase("CVE-2025-52494", ["CWE-770"]),
    SuggestCweCase("CVE-2025-57803", ["CWE-787", "CWE-131"]),
    SuggestCweCase("CVE-2025-58446", ["CWE-770"]),
    SuggestCweCase("CVE-2025-59956", ["CWE-940"]),
    SuggestCweCase("CVE-2025-61584", ["CWE-94"]),
]
# fmt: on

# evaluators
evals = common_feature_evals + [
    SuggestCweEvaluator(),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_cwe():
    """suggest_cwe evaluation entry point"""
    await run_evaluation(cases, evals, suggest_cwe)
