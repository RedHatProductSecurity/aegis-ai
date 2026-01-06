import pytest
import re

from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestCWE, SuggestCWEModel

from evals.features.common import (
    common_feature_evals,
    reflect_confidence,
    run_evaluation,
)


class SuggestCweCase(Case):
    def __init__(self, cve_id, cwe_list, **kwargs):
        """cve_id given as CVE-YYYY-NUM is the flaw we query CWE for.  cwe_list
        is the list of acceptable CWEs, the most preferred one comes first"""
        super().__init__(
            name=f"suggest-cwe-for-{cve_id}",
            inputs=cve_id,
            expected_output=cwe_list,
            **kwargs,
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

    def evaluate(self, ctx: EvaluatorContext[str, SuggestCWEModel]) -> EvaluationReason:
        """return score based on actual and expected results"""
        cwe_list_out = ctx.output.cwe
        cwe_list_exp = ctx.expected_output
        score = self._base_score(cwe_list_out, cwe_list_exp)

        # check how many CWEs were suggested and how man CWEs are accepted
        len_diff = len(cwe_list_out) - len(ctx.expected_output)  # type: ignore
        if 0 < len_diff:
            # penalize too many suggested CWEs for a CVE
            score *= 0.9**len_diff

        reason = None
        if score < 1.0:
            reason = f"got {cwe_list_out}, expected {cwe_list_exp}"

        score = reflect_confidence(ctx, score)
        return EvaluationReason(value=score, reason=reason)


async def suggest_cwe(cve_id: CVEID) -> SuggestCWEModel:
    """use rh_feature_agent to suggest CWE(s) for the given CVE"""
    feature = SuggestCWE(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# evaluation cases
# TODO: gradually remove known_to_fail_evaluators annotations where possible
cases = [
    SuggestCweCase(
        cve_id="CVE-2022-48701",
        cwe_list=["CWE-125", "CWE-20"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-49669",
        cwe_list=["CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-49885",
        cwe_list=["CWE-190"],
    ),
    SuggestCweCase(
        # kdudka: CWE-131 is closely related and applicable IMO
        cve_id="CVE-2022-50235",
        cwe_list=["CWE-805", "CWE-131"],
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50361",
        cwe_list=["CWE-459"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50421",
        cwe_list=["CWE-1341"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50439",
        cwe_list=["CWE-908"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50448",
        cwe_list=["CWE-477"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50470",
        cwe_list=["CWE-1341"],
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50471",
        cwe_list=["CWE-1341"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50477",
        cwe_list=["CWE-772"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50494",
        cwe_list=["CWE-366", "CWE-821"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50554",
        cwe_list=["CWE-820"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50558",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53116",
        cwe_list=["CWE-763"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53123",
        cwe_list=["CWE-763"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53165",
        cwe_list=["CWE-908"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53174",
        cwe_list=["CWE-772", "CWE-459"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53222",
        cwe_list=["CWE-190"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53225",
        cwe_list=["CWE-459"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53394",
        cwe_list=["CWE-821"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53459",
        cwe_list=["CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53487",
        cwe_list=["CWE-276"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    # FIXME: CWE-665 is not included in the CWE-699 view!
    # SuggestCweCase(
    #     cve_id="CVE-2023-53491",
    #     cwe_list=["CWE-665"],
    # ),
    SuggestCweCase(
        cve_id="CVE-2023-53499",
        cwe_list=["CWE-459", "CWE-772"],  # kdudka: added CWE-772
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53510",
        cwe_list=["CWE-821"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53519",
        cwe_list=["CWE-820"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53525",
        cwe_list=["CWE-908"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53531",
        cwe_list=["CWE-366"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53535",
        cwe_list=["CWE-787"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53843",
        cwe_list=["CWE-1284", "CWE-1285", "CWE-681"],  # kdudka: added CWE-1285
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53555",
        cwe_list=["CWE-824"],
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53590",
        cwe_list=["CWE-1050"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53625",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53659",
        cwe_list=["CWE-125"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53703",
        cwe_list=["CWE-1335"],
    ),
    SuggestCweCase(
        cve_id="CVE-2024-41010",
        cwe_list=["CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2024-53147",
        cwe_list=["CWE-787"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2024-53152",
        cwe_list=["CWE-459"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2024-53161",
        cwe_list=["CWE-190", "CWE-1335"],
    ),
    SuggestCweCase(
        cve_id="CVE-2024-53232",
        cwe_list=["CWE-476", "CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2024-56597",
        cwe_list=["CWE-392"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2024-56658",
        cwe_list=["CWE-825"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-5302",
        cwe_list=["CWE-770"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-5399",
        cwe_list=["CWE-835", "CWE-400"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-6547",
        cwe_list=["CWE-347"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    # kdudka: according to Comment#0, CWE-367 and CWE-377 are also applicable, and CWE-378 is in OSIM
    SuggestCweCase(
        cve_id="CVE-2025-7647",
        cwe_list=["CWE-379", "CWE-367", "CWE-377", "CWE-378"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-9319",
        cwe_list=["CWE-494"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-9390",
        cwe_list=["CWE-120"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-9394",
        cwe_list=["CWE-825"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-11429",
        cwe_list=["CWE-613"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-12110",
        cwe_list=["CWE-613"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-12200",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-21640",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-21690",
        cwe_list=["CWE-779"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-21879",
        cwe_list=["CWE-763"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-22097",
        cwe_list=["CWE-824", "CWE-825"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-22115",
        cwe_list=["CWE-413"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-23130",
        cwe_list=["CWE-770"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-23395",
        cwe_list=["CWE-271", "CWE-250", "CWE-272", "CWE-273"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-26503",
        cwe_list=["CWE-120", "CWE-787"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-37996",
        cwe_list=["CWE-824"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38000",
        cwe_list=["CWE-763", "CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38001",
        cwe_list=["CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38509",
        cwe_list=["CWE-1173"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38512",
        cwe_list=[
            "CWE-354",
            "CWE-290",
            "CWE-1287",
        ],  # kdudka: added CWE-290 and CWE-1287
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38562",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38575",
        cwe_list=["CWE-212"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38587",
        cwe_list=["CWE-835"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38691",
        cwe_list=["CWE-824"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38695",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39677",
        cwe_list=["CWE-191"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39739",
        cwe_list=["CWE-358"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39750",
        cwe_list=["CWE-459"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39798",
        cwe_list=["CWE-270"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39855",
        cwe_list=["CWE-476"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39856",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39861",
        cwe_list=["CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39864",
        cwe_list=["CWE-763", "CWE-825"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39865",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39866",
        cwe_list=["CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39915",
        cwe_list=["CWE-833"],
    ),
    # Aegis suggests ['CWE-843', 'CWE-787', 'CWE-476']
    # CWE-787 (Out-of-bounds Write) is close
    # CWE-125 (Out-of-bounds Read) is correct though
    SuggestCweCase(
        cve_id="CVE-2025-39939",
        cwe_list=["CWE-125"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39992",
        cwe_list=["CWE-820"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39999",
        cwe_list=["CWE-1341"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-40265",
        cwe_list=["CWE-252", "CWE-253"],  # kdudka: added CWE-253
    ),
    SuggestCweCase(
        cve_id="CVE-2025-40779",
        cwe_list=["CWE-617", "CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-43529",
        cwe_list=["CWE-825"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-49133",
        cwe_list=["CWE-125"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-52099",
        cwe_list=["CWE-190"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-52494",
        cwe_list=["CWE-770"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-54770",
        cwe_list=["CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-54771",
        cwe_list=["CWE-825"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-55559",
        cwe_list=["CWE-1288"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-57803",
        cwe_list=["CWE-787", "CWE-131"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-58446",
        cwe_list=["CWE-770"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-59303",
        cwe_list=["CWE-497", "CWE-807"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-59681",
        cwe_list=["CWE-89"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-59956",
        cwe_list=["CWE-940"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-61584",
        cwe_list=["CWE-94"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-61663",
        cwe_list=["CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-61770",
        cwe_list=["CWE-131"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-61771",
        cwe_list=["CWE-131"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-61984",
        cwe_list=["CWE-78"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-61985",
        cwe_list=["CWE-88", "CWE-1286"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-63811",
        cwe_list=["CWE-770"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-67639",
        cwe_list=["CWE-613"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
]

# evaluators
evals = common_feature_evals + [
    SuggestCweEvaluator(),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_cwe():
    """suggest_cwe evaluation entry point"""
    await run_evaluation(cases, evals, suggest_cwe)
