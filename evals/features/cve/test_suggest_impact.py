import cvss
import pytest

from typing import get_args

from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestImpact, SuggestImpactModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    make_eval_reason,
    reflect_confidence,
    run_evaluation,
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


# TODO: check whether the cvss Python module could anyhow help with this
def score_cvss3_diff(cvss3: str, cvss3_exp: str) -> tuple[float, str | None]:
    """Compare two CVSS 3.1 vectors and return (score, reason).
    0.0 means completely different, 1.0 means exact match.
    When the score is not 1.0, reason enumerates mismatched metrics."""
    if cvss3 == cvss3_exp:
        # exact match
        return (1.0, None)

    def _parse(v: str) -> dict[str, str]:
        parts = v.split("/")
        if parts and parts[0].startswith("CVSS:"):
            parts = parts[1:]
        out: dict[str, str] = {}
        for p in parts:
            if ":" in p:
                k, val = p.split(":", 1)
                out[k] = val
        return out

    a = _parse(cvss3)
    b = _parse(cvss3_exp)

    # Ordinal scales per CVSS v3.1 base metric
    scales: dict[str, list[str]] = {
        "AV": ["P", "L", "A", "N"],
        "AC": ["H", "L"],
        "PR": ["H", "L", "N"],
        "UI": ["R", "N"],
        "S": ["U", "C"],
        "C": ["N", "L", "H"],
        "I": ["N", "L", "H"],
        "A": ["N", "L", "H"],
    }

    def _norm_dist(metric: str) -> float:
        order = scales[metric]
        try:
            ia = order.index(a.get(metric, ""))
            ib = order.index(b.get(metric, ""))
        except ValueError:
            # unknown value → treat as maximum difference
            return 1.0
        max_d = len(order) - 1
        if max_d == 0:
            return 0.0
        return abs(ia - ib) / max_d

    metrics = tuple(scales.keys())
    diffs = [_norm_dist(m) for m in metrics]
    avg_diff = sum(diffs) / len(diffs)
    score = (1.0 - avg_diff) ** 2

    # Build human-friendly reason for mismatches
    mismatch_list: list[str] = []
    for m in metrics:
        va = a.get(m)
        vb = b.get(m)
        if va is None or vb is None:
            continue
        if va != vb:
            mismatch_list.append(f"{m}: got {va}, expected {vb}")

    reason = "mismatched metrics: " + "; ".join(mismatch_list)
    return (score, reason)


class ImpactEvaluator(Evaluator[str, SuggestImpactModel]):
    def evaluate(self, ctx: EvaluatorContext[str, SuggestImpactModel]) -> float:
        """return score based on actual and expected impact"""
        assert ctx.expected_output is not None

        # compare actual and expected impact
        imp = NUM_BY_IMPACT[ctx.output.impact]
        imp_exp = NUM_BY_IMPACT[ctx.expected_output.impact]
        score = 1.0 - abs(imp - imp_exp) / 10.0

        return reflect_confidence(ctx, score)


class CVSSScoreEvaluator(Evaluator[str, SuggestImpactModel]):
    def evaluate(self, ctx: EvaluatorContext[str, SuggestImpactModel]) -> float:
        """return score based on actual and expected CVSS score"""
        assert ctx.expected_output is not None

        try:
            # compare actual and expected cvss3_score
            cvss3 = float(ctx.output.cvss3_score)
            cvss3_exp = float(ctx.expected_output.cvss3_score)
            score = 1.0 - abs(cvss3 - cvss3_exp) / 10.0
        except ValueError:
            # the provided cvss3_score field is not a number
            score = 0.0

        return reflect_confidence(ctx, score)


class CVSSVectorEvaluator(Evaluator[str, SuggestImpactModel]):
    def evaluate(
        self, ctx: EvaluatorContext[str, SuggestImpactModel]
    ) -> EvaluationReason:
        """return score based on actual and expected CVSS vector and include a reason when the score is low"""
        assert ctx.expected_output is not None

        # get actual and expected cvss3_vector
        cvss3 = ctx.output.cvss3_vector
        cvss3_exp = ctx.expected_output.cvss3_vector
        assert cvss3 and cvss3_exp

        # compare the vectors by individual metrics
        try:
            score, reason = score_cvss3_diff(cvss3, cvss3_exp)
        except Exception as e:
            # parsing or comparison failed -> no credit
            score = 0.0
            reason = f"unhandled exception: {e}"

        score = reflect_confidence(ctx, score)
        return EvaluationReason(value=score, reason=reason)


# some evaluators are only applicable if the expected output for a specific field is provided
field_evaluators = {
    "impact": ImpactEvaluator(),
    "cvss3_score": CVSSScoreEvaluator(),
    "cvss3_vector": CVSSVectorEvaluator(),
}


class SuggestImpactCase(Case):
    def __init__(
        self,
        cve_id,
        expected_impact=None,
        expected_cvss3_score=None,
        expected_cvss3_vector=None,
        **kwargs,
    ):
        """evaluation case for suggest-impact, cve_id is the input, expected_* is the expected output"""
        disclaimer_model = SuggestImpactModel.model_fields["disclaimer"]
        disclaimer = get_args(disclaimer_model.annotation)[0]

        if not expected_cvss3_score:
            # no expected CVSS3 score provided
            if expected_cvss3_vector:
                # use the provided CVSS3 vector to compute the expected score
                expected_cvss3_score = cvss.CVSS3(expected_cvss3_vector).scores()[0]
            else:
                # do not evaluate CVSS3 score
                expected_cvss3_score = ""

        expected_output = SuggestImpactModel(
            cve_id=cve_id,
            title="",
            components=[],
            affected_products=[],
            explanation="",
            impact=expected_impact,
            cvss3_score=str(expected_cvss3_score),
            cvss3_vector=expected_cvss3_vector,
            confidence=1.0,
            tools_used=[],
            disclaimer=disclaimer,
        )

        # enable field-specific evaluators for this case
        evaluators = tuple(
            field_evaluators[f] for f in field_evaluators if getattr(expected_output, f)
        )

        super().__init__(
            name=f"suggest-impact-for-{cve_id}",
            inputs=cve_id,
            expected_output=expected_output,
            evaluators=evaluators,
            **kwargs,
        )


class CVSSValidator(Evaluator[str, SuggestImpactModel]):
    async def evaluate(self, ctx) -> EvaluationReason:
        """verify that cvss3_score and cvss3_vector are consistent"""
        try:
            # parse cvss3_score as float
            cvss3_score = float(ctx.output.cvss3_score)
        except Exception:
            return make_eval_reason(
                fail_reason=f"failed to parse cvss3_score: {ctx.output.cvss3_score}"
            )

        try:
            # parse cvss3_vector and compute the CVSS 3.1 score from it
            cvss3_vector = ctx.output.cvss3_vector
            cvss3_score_by_vector = cvss.CVSS3(cvss3_vector).scores()[0]
        except Exception:
            return make_eval_reason(
                fail_reason=f"failed to parse cvss3_vector: {cvss3_vector}"
            )

        if cvss3_score != cvss3_score_by_vector:
            return make_eval_reason(
                fail_reason=f"suggested cvss3_score ({cvss3_score}) does not match suggested cvss3_vector ({cvss3_score_by_vector} {cvss3_vector})"
            )

        # no problem detected
        return EvaluationReason(True)


async def suggest_impact(cve_id: CVEID) -> SuggestImpactModel:
    """use rh_feature_agent to suggest Impact for the given CVE"""
    feature = SuggestImpact(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    SuggestImpactCase(
        cve_id="CVE-2022-23125",
        expected_cvss3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    SuggestImpactCase(
        cve_id="CVE-2022-48701",
        expected_impact="MODERATE",
        expected_cvss3_score=4.9,
    ),
    SuggestImpactCase(
        cve_id="CVE-2023-39326",
        expected_impact="MODERATE",
        expected_cvss3_score=7.5,
    ),
    # FIXME: scope is wrong (Aegis suggests S:C while S:U is expected)
    SuggestImpactCase(
        cve_id="CVE-2023-53222",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H",
        metadata={"known_to_fail_evaluators": ["CVSSVectorEvaluator"]},
    ),
    SuggestImpactCase(
        cve_id="CVE-2023-53491",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H",
    ),
    SuggestImpactCase(
        cve_id="CVE-2023-53510",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H",
    ),
    SuggestImpactCase(
        cve_id="CVE-2023-53693",
        expected_impact="MODERATE",
        expected_cvss3_score=5.5,
    ),
    SuggestImpactCase(
        cve_id="CVE-2023-53733",
        expected_impact="MODERATE",
        expected_cvss3_score=5.5,
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
    ),
    SuggestImpactCase(
        cve_id="CVE-2023-53843",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H",
    ),
    SuggestImpactCase(
        cve_id="CVE-2024-53232",
        expected_impact="MODERATE",
        expected_cvss3_score=4.4,
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-5399",
        expected_impact="MODERATE",
        expected_cvss3_score=4.3,
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-9573",
        expected_impact="IMPORTANT",
        expected_cvss3_score=7.2,
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-12735",
        expected_impact="CRITICAL",
        expected_cvss3_score=9.8,
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-12816",
        expected_impact="IMPORTANT",
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-13609",
        expected_cvss3_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L",
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-23395",
        expected_impact="MODERATE",
        expected_cvss3_score=6.8,
    ),
    # FIXME: According to feedback by a security analyst, Aegis should suggest no impact on CIA
    SuggestImpactCase(
        cve_id="CVE-2025-37798",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
        metadata={
            "known_to_fail_evaluators": ["CVSSVectorEvaluator", "CVSSScoreEvaluator"]
        },
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-38512",
        expected_cvss3_vector="CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L",
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-39677",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H",
    ),
    # FIXME: According to feedback by a security analyst, Aegis currently suggests a wrong vector
    SuggestImpactCase(
        cve_id="CVE-2025-39922",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H",
        metadata={"known_to_fail_evaluators": ["CVSSVectorEvaluator"]},
    ),
    # FIXME: According to feedback by a security analyst, Aegis currently suggests a wrong vector
    SuggestImpactCase(
        cve_id="CVE-2025-39939",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:H",
        metadata={"known_to_fail_evaluators": ["CVSSVectorEvaluator"]},
    ),
    # FIXME: scope is wrong (Aegis suggests S:C while S:U is expected)
    SuggestImpactCase(
        cve_id="CVE-2025-40320",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:H/A:H",
        metadata={"known_to_fail_evaluators": ["CVSSVectorEvaluator"]},
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-53000",
        expected_cvss3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-59840",
        expected_impact="IMPORTANT",
        expected_cvss3_score=8.1,
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-64524",
        expected_impact="MODERATE",
        expected_cvss3_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H",
    ),
    SuggestImpactCase(
        cve_id="CVE-2025-66448",
        expected_impact="IMPORTANT",
    ),
]

# evaluators
evals = common_feature_evals + [
    CVSSValidator(),
    create_llm_judge(
        assertion_name="NoAffectsInExplanation",
        rubric="The 'explanation' output field does not list affected Red Hat products.  Red Hat is not a product.",
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_impact():
    """suggest_impact evaluation entry point"""
    await run_evaluation(cases, evals, suggest_impact)
