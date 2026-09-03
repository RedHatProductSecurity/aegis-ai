"""
Suggest affected packages evaluation suite.

Uses osidb_cache CVE data. Input: cve_id. The feature analyzes OSIDB affects
(with PURLs and product streams) to suggest which source RPM packages are
affected by the vulnerability.

Requires cache entries with affects data including ``purl`` and
``ps_update_stream`` fields.  To populate, re-fetch qualifying CVEs with
``include_affects=True`` in ``write_cache_entry()``.

Runnable: pytest evals/features/cve/test_suggest_affected_packages.py
Optional: --sample N or AEGIS_EVALS_SUGGEST_AFFECTED_PACKAGES_SAMPLE=N
"""

import logging
import os
import random
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestAffectedPackages
from aegis_ai.features.cve.data_models import SuggestAffectedPackagesModel
from aegis_ai.toolsets.tools.osidb import CVE
from evals.features.common import (
    FeatureMetricsEvaluator,
    ToolsUsedEvaluator,
    reflect_confidence,
    run_evaluation,
)
from evals.utils.osidb_cache import OSIDB_CACHE_DIR

logger = logging.getLogger(__name__)

SAMPLE_SEED = int(os.getenv("AEGIS_EVALS_SUGGEST_AFFECTED_PACKAGES_SAMPLE_SEED", "42"))

# CVE IDs with OSIDB cache entries that include affects with purl and
# ps_update_stream fields.  Populate by re-fetching qualifying CVEs with
# include_affects=True in write_cache_entry().
DEFAULT_CVE_IDS: tuple[str, ...] = (
    "CVE-2014-9984",
    "CVE-2025-49175",
    "CVE-2026-3904",
    "CVE-2026-34982",
)


KNOWN_TO_FAIL_CVE_IDS: tuple[str, ...] = ()


def _affects_with_purls(cve: CVE) -> list[dict[str, Any]]:
    """Return affect entries that have both purl and ps_update_stream."""
    if not cve.affects:
        return []
    return [
        a
        for a in cve.affects
        if isinstance(a, dict) and a.get("purl") and a.get("ps_update_stream")
    ]


def _load_qualifying_cves(
    cve_id_filter: set[str] | None = None,
) -> list[tuple[str, CVE, list[dict[str, Any]]]]:
    """Load CVEs from osidb_cache that have affects with PURLs."""
    cache_path = Path(OSIDB_CACHE_DIR)
    if not cache_path.is_dir():
        logger.warning("OSIDB_CACHE_DIR %s is not a directory", OSIDB_CACHE_DIR)
        return []

    qualifying = []
    for json_file in sorted(cache_path.glob("CVE-*.json")):
        cve_id = json_file.stem
        if cve_id_filter is not None and cve_id not in cve_id_filter:
            continue
        try:
            with open(json_file, "r") as f:
                cve = CVE.model_validate_json(f.read())
        except Exception as e:
            logger.debug("Skip %s: %s", cve_id, e)
            continue

        affected = _affects_with_purls(cve)
        if not affected:
            continue
        qualifying.append((cve_id, cve, affected))

    return qualifying


def _build_cases(
    sample_size: int | None = None,
    seed: int = SAMPLE_SEED,
    cve_id_filter: set[str] | None = None,
) -> list["SuggestAffectedPackagesCase"]:
    """Build cases from osidb_cache; optionally sample N."""
    qualifying = _load_qualifying_cves(cve_id_filter=cve_id_filter)
    cases = []

    for cve_id, cve, affected in qualifying:
        expected_pairs = [
            (a["purl"], a["ps_update_stream"])
            for a in affected
            if a.get("affected") == "AFFECTED"
        ]
        metadata: dict[str, Any] = {"cve_id": cve_id}
        if cve_id in KNOWN_TO_FAIL_CVE_IDS:
            metadata["known_to_fail_evaluators"] = ["PackageOverlapEvaluator"]

        case = SuggestAffectedPackagesCase(
            name=f"suggest-affected-packages-{cve_id}",
            inputs=cve_id,
            expected_output=expected_pairs,
            metadata=metadata,
            evaluators=(),
        )
        cases.append(case)

    if sample_size is not None and sample_size < len(cases):
        rng = random.Random(seed)
        cases = rng.sample(cases, sample_size)
        logger.info(
            "Sampled %d cases from %d qualifying (seed=%d)",
            sample_size,
            len(qualifying),
            seed,
        )

    return cases


class SuggestAffectedPackagesCase(Case):
    """Evaluation case: inputs = cve_id, expected_output = list of (purl, ps_update_stream) pairs."""

    inputs: str
    expected_output: list[tuple[str, str]]


def _normalize_pair(purl: str, stream: str) -> tuple[str, str]:
    return (purl.lower().strip(), stream.lower().strip())


class PackageOverlapEvaluator(Evaluator[str, SuggestAffectedPackagesModel]):
    """Scores overlap between suggested and expected affected (purl, ps_update_stream) pairs.

    Uses Jaccard similarity so that the same PURL in different streams is
    treated as a distinct entry.
    """

    def evaluate(
        self, ctx: EvaluatorContext[str, SuggestAffectedPackagesModel]
    ) -> EvaluationReason:
        expected_pairs = cast(list[tuple[str, str]], ctx.expected_output or [])
        suggested = getattr(ctx.output, "affected_packages", None) or []
        got_pairs = [(p.purl, p.ps_update_stream) for p in suggested if p.affected]

        exp_set = {_normalize_pair(*p) for p in expected_pairs}
        got_set = {_normalize_pair(*p) for p in got_pairs}

        if not exp_set:
            score = 1.0 if not got_set else 0.0
            reason = (
                None if score == 1.0 else f"got {got_pairs}, expected {expected_pairs}"
            )
            return EvaluationReason(value=score, reason=reason)

        if exp_set == got_set:
            return EvaluationReason(value=reflect_confidence(ctx, 1.0), reason=None)

        inter = len(exp_set & got_set)
        union = len(exp_set | got_set)
        score = inter / union if union else 0.0
        reason = f"got {got_pairs}, expected {expected_pairs}"
        score = reflect_confidence(ctx, score)
        return EvaluationReason(value=score, reason=reason)


async def suggest_affected_packages(cve_id: CVEID) -> SuggestAffectedPackagesModel:
    """Run SuggestAffectedPackages for the given CVE."""
    feature = SuggestAffectedPackages(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


evals = [
    FeatureMetricsEvaluator(),
    ToolsUsedEvaluator(),
    PackageOverlapEvaluator(),
]


@pytest.fixture(scope="session")
def suggest_affected_packages_cases(request):
    """Build cases from osidb_cache."""
    sample_size = request.config.getoption("sample", default=None)
    if sample_size is None:
        env_val = os.getenv("AEGIS_EVALS_SUGGEST_AFFECTED_PACKAGES_SAMPLE")
        if env_val:
            try:
                sample_size = int(env_val)
            except ValueError:
                sample_size = None

    raw = os.getenv("AEGIS_EVALS_SUGGEST_AFFECTED_PACKAGES_CVE_IDS", "").strip()
    if raw:
        cve_id_filter = {cve_id.strip() for cve_id in raw.split(",") if cve_id.strip()}
    else:
        cve_id_filter = set(DEFAULT_CVE_IDS) if DEFAULT_CVE_IDS else None
    return _build_cases(
        sample_size=sample_size,
        seed=SAMPLE_SEED,
        cve_id_filter=cve_id_filter,
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_eval_suggest_affected_packages(suggest_affected_packages_cases):
    """Suggest affected packages evaluation entry point."""
    if not suggest_affected_packages_cases:
        pytest.skip(
            "No qualifying cases in osidb_cache (need affects with purl and "
            "ps_update_stream fields). Re-fetch CVEs with include_affects=True."
        )
    await run_evaluation(
        suggest_affected_packages_cases,
        evals,
        suggest_affected_packages,
        agent=rh_feature_agent,
    )
