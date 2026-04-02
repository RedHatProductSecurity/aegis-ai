"""Evaluate suggest-impact on the 36 kernel CVEs from al-kernel-cves.csv.

Runs the full AEGIS pipeline (LLM + OSIDB + kernel classifier tool) and
compares predicted impact/CVSS against manually-verified expected values.

Includes an UnderestimationEvaluator that flags predictions where the model
assigns a lower severity than the ground truth — these are critical failures
per the project's asymmetric error policy.

After each run, a structured JSON export of per-case results (predictions,
explanations, classifier diagnostics, evaluator outcomes) is written to
``kernel_eval_results.json`` in this directory for post-hoc analysis.
"""

import csv
from pathlib import Path

import pytest
from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestImpact, SuggestImpactModel

from evals.features.common import (
    common_feature_evals,
    export_eval_results,
    run_evaluation,
)
from evals.features.cve.test_suggest_impact import (
    CVSSScoreEvaluator,
    CVSSValidator,
    ImpactEvaluator,
    SuggestImpactCase,
)

CSV_PATH = Path(__file__).resolve().parent / "al-kernel-cves.csv"
RESULTS_PATH = Path(__file__).resolve().parent / "kernel_eval_results.json"

SEVERITY_RANK = {"CRITICAL": 0, "IMPORTANT": 1, "MODERATE": 2, "LOW": 3, "NONE": 4}

# Cases where underestimation failures are expected due to structural gaps
# that cannot be resolved by prompt or classifier tuning alone.  Each entry
# maps a CVE ID to a dict with ``known_to_fail_evaluators`` (list of
# evaluator class names to waive) and a ``reason`` explaining why.
#
# Failure categories (from cascade trace analysis of al-kernel-cves.csv):
#
#   Cascade gap — no escalation rule covers the pattern:
#     CVE-2025-37803: kernel_panic + memory without network exposure;
#       CVSS 7.0 is below R9/R10 thresholds, R11/R12 don't match.
#     CVE-2022-50873: kernel_panic_plus_uaf detected by NN but not by
#       XGBoost feature extractor; R11 cannot fire.  Expected CVSS (6.2)
#       also too low for R9/R10.
#     CVE-2023-54258: kernel_panic detected by NN but not by classifier;
#       R12 cannot fire despite servertoclientfail flag being present.
#
#   Non-deterministic LLM border — cascade SHOULD handle these when CVSS
#   data is available, but LLM sometimes produces sub-7.0 scores:
#     CVE-2026-23074: R6+R12 should escalate LOW→MODERATE→IMPORTANT
#       when NIST CVSS ≥ 6.7, but classifier fallback depends on OSIDB
#       availability.
#     CVE-2023-53186: same R6+R12 path; intermittent.
#
# To waive an evaluator for a case, add its CVE ID here.  Review
# kernel_eval_results.json after each run to confirm before waiving.
KNOWN_FAILURES: dict[str, dict] = {
    # Uncomment entries below after confirming with kernel_eval_results.json
    # that the failure is structural and not a transient regression.
    #
    # "CVE-2025-37803": {
    #     "known_to_fail_evaluators": ["UnderestimationEvaluator"],
    #     "reason": "cascade gap: kernel_panic+memory without network exposure",
    # },
    # "CVE-2022-50873": {
    #     "known_to_fail_evaluators": ["UnderestimationEvaluator"],
    #     "reason": "feature extraction gap: kernel_panic_plus_uaf not detected",
    # },
    # "CVE-2023-54258": {
    #     "known_to_fail_evaluators": ["UnderestimationEvaluator"],
    #     "reason": "feature extraction gap: kernel_panic not detected by classifier",
    # },
}


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

            metadata = KNOWN_FAILURES.get(cve_id)
            cases.append(
                SuggestImpactCase(
                    cve_id=cve_id,
                    expected_impact=expected_impact,
                    expected_cvss3_score=expected_cvss,
                    metadata=metadata,
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


async def test_eval_suggest_impact_kernel_cves():
    """suggest_impact evaluation on al-kernel-cves.csv CVEs"""
    report = await run_evaluation(cases, evals, suggest_impact, agent=rh_feature_agent)
    export_eval_results(report, RESULTS_PATH)
