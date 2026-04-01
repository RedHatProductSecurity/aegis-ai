"""Evaluate suggest-impact on the 36 kernel CVEs from al-kernel-cves.csv.

Runs the full AEGIS pipeline (LLM + OSIDB + kernel classifier tool) and
compares predicted impact/CVSS against manually-verified expected values.

Includes an UnderestimationEvaluator that flags predictions where the model
assigns a lower severity than the ground truth — these are critical failures
per the project's asymmetric error policy.
"""

import csv
from pathlib import Path

import pytest
from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestImpact, SuggestImpactModel

from evals.features.common import common_feature_evals, run_evaluation
from evals.features.cve.test_suggest_impact import (
    CVSSScoreEvaluator,
    CVSSValidator,
    ImpactEvaluator,
    SuggestImpactCase,
)

CSV_PATH = Path(__file__).resolve().parent / "al-kernel-cves.csv"

SEVERITY_RANK = {"CRITICAL": 0, "IMPORTANT": 1, "MODERATE": 2, "LOW": 3, "NONE": 4}


def _normalize_impact(raw: str) -> str:
    """'Important' -> 'IMPORTANT', 'Moderate <= 5.5' -> 'MODERATE'"""
    return raw.strip().split()[0].upper()


class UnderestimationEvaluator(Evaluator[str, SuggestImpactModel]):
    """Fail when the predicted impact is strictly lower than expected.

    Underestimation means a high-impact vulnerability ships without the
    urgency it deserves.  Overestimation merely triggers extra review.
    """

    def evaluate(
        self, ctx: EvaluatorContext[str, SuggestImpactModel]
    ) -> EvaluationReason:
        assert ctx.expected_output is not None
        actual = (ctx.output.impact or "").strip().upper()
        expected = (ctx.expected_output.impact or "").strip().upper()

        if not actual or not expected:
            return EvaluationReason(value=True)

        actual_rank = SEVERITY_RANK.get(actual, 4)
        expected_rank = SEVERITY_RANK.get(expected, 4)

        if actual_rank > expected_rank:
            return EvaluationReason(
                value=False,
                reason=f"underestimation: predicted {actual}, expected {expected}",
            )
        return EvaluationReason(value=True)


def _load_cases() -> list[SuggestImpactCase]:
    cases = []
    seen = set()
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if not row or not row[0].strip().startswith("CVE-"):
                continue
            cve_id = row[0].strip()
            if cve_id in seen:
                continue
            seen.add(cve_id)

            expected_impact = _normalize_impact(row[1])
            try:
                expected_cvss = float(row[2].strip())
            except ValueError:
                expected_cvss = None

            cases.append(
                SuggestImpactCase(
                    cve_id=cve_id,
                    expected_impact=expected_impact,
                    expected_cvss3_score=expected_cvss,
                )
            )
    return cases


cases = _load_cases()

evals = common_feature_evals + [
    ImpactEvaluator(),
    CVSSScoreEvaluator(),
    CVSSValidator(),
    UnderestimationEvaluator(),
]


async def suggest_impact(cve_id: CVEID) -> SuggestImpactModel:
    feature = SuggestImpact(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_impact_manual_check():
    """suggest_impact evaluation on al-kernel-cves.csv CVEs"""
    await run_evaluation(cases, evals, suggest_impact, agent=rh_feature_agent)
