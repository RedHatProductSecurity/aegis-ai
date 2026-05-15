import pytest
import re

from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestCWE, SuggestCWEModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
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
        cve_id="CVE-2019-25544",
        cwe_list=["CWE-1284"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-48701",
        cwe_list=["CWE-125", "CWE-20"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-49669",
        cwe_list=["CWE-825", "CWE-366"],  # kdudka: added CWE-366
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
        cve_id="CVE-2022-50333",
        cwe_list=["CWE-1285"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50361",
        cwe_list=["CWE-459"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50390",
        cwe_list=["CWE-1335"],
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50421",
        cwe_list=["CWE-1341"],
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50439",
        cwe_list=["CWE-908"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50448",
        cwe_list=["CWE-477"],
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
    ),
    # FIXME: Aegis occasionally ends up with an empty list when CWE-416 and CWE-415 are filtered out
    SuggestCweCase(
        cve_id="CVE-2022-50470",
        cwe_list=["CWE-1341"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
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
        cve_id="CVE-2022-50736",
        cwe_list=["CWE-125", "CWE-475"],  # kdudka: added CWE-475
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2022-50774",
        cwe_list=["CWE-628"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53116",
        cwe_list=["CWE-763"],
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53123",
        cwe_list=["CWE-763"],
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53165",
        cwe_list=["CWE-908"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53174",
        cwe_list=["CWE-772", "CWE-459"],
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53176",
        cwe_list=["CWE-772", "CWE-825"],  # kdudka: added CWE-825
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53188",
        cwe_list=["CWE-821", "CWE-835"],  # kdudka: added CWE-835
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
        cve_id="CVE-2023-53333",
        cwe_list=["CWE-125", "CWE-805"],  # kdudka: added CWE-805
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
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
    ),
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
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
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
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
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
        cve_id="CVE-2023-53764",
        cwe_list=["CWE-414", "CWE-413"],  # kdudka: added CWE-413
        metadata={"known_to_fail_evaluators": ["CWEExplanationRootCause"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-53843",
        cwe_list=["CWE-1284", "CWE-1285", "CWE-681"],  # kdudka: added CWE-1285
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2023-54201",
        cwe_list=["CWE-911", "CWE-191"],  # kdudka: added CWE-191
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
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
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
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
        metadata={"known_to_fail_evaluators": ["CWEExplanationRootCause"]},
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
    # FIXME: Aegis occasionally suggests CWE-770, which is similar but not accurate
    SuggestCweCase(
        cve_id="CVE-2025-21690",
        cwe_list=["CWE-779"],
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
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
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ],
        },
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
    # FIXME: we have no solid input data for CVE-2025-26503
    SuggestCweCase(
        cve_id="CVE-2025-26503",
        cwe_list=["CWE-120", "CWE-787", "CWE-124"],
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2025-37996",
        cwe_list=["CWE-824"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38000",
        cwe_list=["CWE-763", "CWE-825"],
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38001",
        cwe_list=["CWE-825"],
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
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
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2025-38587",
        cwe_list=["CWE-835"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
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
    # Aegis suggests CWE-823 (Unnecessary Inclusion of Sensitive Information in Debug Log)
    # while explaining "memory allocation failures and out-of-range memory access".
    # The model appears to confuse the `arm_smmu_context_fault` log output in the bug
    # description with an information-disclosure weakness, producing an incoherent
    # CWE/explanation pair. The correct CWE is CWE-358 (missing IOMMU workaround entry).
    SuggestCweCase(
        cve_id="CVE-2025-39739",
        cwe_list=["CWE-358"],
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39750",
        cwe_list=["CWE-459"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39754",
        cwe_list=["CWE-820", "CWE-413"],  # kdudka: added CWE-413
        # LLM returns CWE-708 (Incorrect Ownership Assignment) instead of
        # CWE-820/CWE-413 (Missing Synchronization / Improper Resource Locking).
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39782",
        cwe_list=["CWE-413", "CWE-821", "CWE-833"],  # kdudka: added CWE-821 and CWE-833
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39791",
        cwe_list=["CWE-440"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39792",
        cwe_list=["CWE-833", "CWE-821"],  # kdudka: added CWE-821
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39795",
        cwe_list=["CWE-190"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39798",
        cwe_list=["CWE-270"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39808",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39809",
        cwe_list=["CWE-805", "CWE-787", "CWE-131"],  # kdudka: added CWE-787 and CWE-131
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39810",
        cwe_list=["CWE-131"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39816",
        cwe_list=["CWE-367", "CWE-805"],  # kdudka: added CWE-805
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39822",
        cwe_list=["CWE-681", "CWE-190"],  # kdudka: added CWE-190
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
    # LLM judge hallucinated CWE-366 name ("Improper Handling of File Names")
    # when CWE-366 is actually "Race Condition within a Thread" — which does
    # relate to the race condition → UAF flaw described in the explanation.
    SuggestCweCase(
        cve_id="CVE-2025-39866",
        cwe_list=["CWE-825"],
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
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
        cve_id="CVE-2025-39994",
        cwe_list=["CWE-825"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-39999",
        cwe_list=["CWE-1341"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-40109",
        cwe_list=["CWE-331"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-40265",
        cwe_list=["CWE-252", "CWE-253"],  # kdudka: added CWE-253
    ),
    SuggestCweCase(
        cve_id="CVE-2025-40779",
        cwe_list=["CWE-617", "CWE-476"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
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
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
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
        cve_id="CVE-2025-56005",
        cwe_list=["CWE-502"],
    ),
    SuggestCweCase(
        cve_id="CVE-2025-57803",
        cwe_list=[
            "CWE-787",
            "CWE-131",
            "CWE-190",
            "CWE-805",
        ],  # kdudka: added CWE-190 and CWE-805
    ),
    SuggestCweCase(
        cve_id="CVE-2025-58446",
        cwe_list=["CWE-770"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-59031",
        cwe_list=["CWE-611", "CWE-22"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2025-59032",
        cwe_list=["CWE-229"],
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
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
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
        metadata={
            "known_to_fail_evaluators": [
                "SuggestCweEvaluator",
                "CWEExplanationRootCause",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2025-69196",
        cwe_list=["CWE-1220"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-3608",
        cwe_list=["CWE-617"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-3644",
        cwe_list=["CWE-791"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-25780",
        cwe_list=["CWE-770"],
    ),
    SuggestCweCase(
        cve_id="CVE-2026-26740",
        cwe_list=["CWE-131", "CWE-787", "CWE-805"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-26939",
        cwe_list=["CWE-1220", "CWE-862", "CWE-266"],
        metadata={
            "known_to_fail_evaluators": [
                "CWEExplanationRootCause",
                "SuggestCweEvaluator",
            ]
        },
    ),
    SuggestCweCase(
        cve_id="CVE-2026-27651",
        cwe_list=["CWE-476"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-27784",
        cwe_list=["CWE-190", "CWE-131", "CWE-805", "CWE-787", "CWE-120", "CWE-125"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    # Aegis suggests CWE-1050 (Excessive Platform Resource Consumption within a Loop),
    # possibly a reasonable alternative for the Dovecot RFC 2231 MIME parameter CPU DoS.
    # Consider broadening cwe_list to ["CWE-770", "CWE-1050"] if CWE-1050 is accepted.
    SuggestCweCase(
        cve_id="CVE-2026-27859",
        cwe_list=["CWE-770"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-28500",
        cwe_list=["CWE-829"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-29063",
        cwe_list=["CWE-915"],
    ),
    SuggestCweCase(
        cve_id="CVE-2026-31966",
        cwe_list=["CWE-125"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-31969",
        cwe_list=["CWE-787", "CWE-193"],  # kdudka: added CWE-193
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-31970",
        cwe_list=["CWE-190"],
    ),
    SuggestCweCase(
        cve_id="CVE-2026-31971",
        cwe_list=["CWE-131", "CWE-130", "CWE-805"],  # CWE-130, CWE-805 added by kdudka
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-31973",
        cwe_list=["CWE-476"],
    ),
    SuggestCweCase(
        cve_id="CVE-2026-32636",
        cwe_list=["CWE-787"],
    ),
    SuggestCweCase(
        cve_id="CVE-2026-33001",
        cwe_list=["CWE-22", "CWE-59"],
    ),
    SuggestCweCase(
        cve_id="CVE-2026-33002",
        cwe_list=["CWE-346", "CWE-940"],  # kdudka: added CWE-940
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-33551",
        cwe_list=["CWE-266"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    # Aegis suggests CWE-763 (Release of Invalid Pointer or Reference) —
    # same CWE-404 family as CWE-1341/CWE-415 but not a precise match for double-free.
    SuggestCweCase(
        cve_id="CVE-2026-33995",
        cwe_list=["CWE-1341", "CWE-415"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-34785",
        cwe_list=["CWE-552", "CWE-73", "CWE-22", "CWE-41"],  # kdudka: added CWE-41
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-35535",
        cwe_list=["CWE-272", "CWE-273"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-35536",
        cwe_list=["CWE-88", "CWE-140", "CWE-93"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-35540",
        cwe_list=["CWE-918"],
        metadata={"known_to_fail_evaluators": ["SuggestCweEvaluator"]},
    ),
    SuggestCweCase(
        cve_id="CVE-2026-40223",
        cwe_list=["CWE-617"],
    ),
]

# evaluators
evals = common_feature_evals + [
    SuggestCweEvaluator(),
    create_llm_judge(
        assertion_name="CWEExplanationRootCause",
        rubric=(
            "Pass if the explanation is non-empty and describes a plausible technical weakness (memory, sync, "
            "injection, resource handling, auth, etc.). CWE selection is often debatable; ranked lists may include "
            "imperfect secondary IDs. Do not fail because one CWE in the list is a stretch or contradicts the narrative "
            "while another CWE in the same list fits. Fail only if the explanation is empty, incoherent, or none of the "
            "listed CWEs could reasonably relate to the described flaw."
        ),
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_cwe():
    """suggest_cwe evaluation entry point"""
    await run_evaluation(cases, evals, suggest_cwe, agent=rh_feature_agent)
