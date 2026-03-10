"""
Suggest affected components evaluation suite.

Uses osidb_cache CVE data. Input: cve_id. The feature uses exclude_osidb_fields=["components"]
so the model infers from title, description, etc. (no cheating).
Runnable: pytest evals/features/cve/test_suggest_affected_components.py
Optional: --sample N or AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE=N
"""

import logging
import os
import random
from pathlib import Path
from typing import cast

import pytest

from pydantic_evals import Case
from pydantic_evals.evaluators import Evaluator, EvaluatorContext

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestAffectedComponents
from aegis_ai.features.cve.data_models import SuggestAffectedComponentsModel
from aegis_ai.toolsets.tools.osidb import CVE, _strip_component_prefix_from_title

from evals.features.common import (
    FeatureMetricsEvaluator,
    ToolsUsedEvaluator,
    reflect_confidence,
    run_evaluation,
)
from evals.utils.osidb_cache import OSIDB_CACHE_DIR

logger = logging.getLogger(__name__)

SAMPLE_SEED = int(
    os.getenv("AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE_SEED", "42")
)

# CVE IDs added in aegis-371 component intelligence eval (evals/osidb_cache).
# Used when AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_CVE_IDS env is not set.
# Excludes CVEs with cpython as expected (model tends to suggest 'python' instead).
# Excludes CVE-2025-23083 (nodejs): model often returns 'Node.js', causing flaky evals.
DEFAULT_CVE_IDS: tuple[str, ...] = (
    "CVE-2025-11233",
    "CVE-2025-12863",
    "CVE-2025-13699",
    "CVE-2025-14087",
    "CVE-2025-22866",
    "CVE-2025-22868",
    "CVE-2025-23050",
    "CVE-2025-3416",
    "CVE-2025-47911",
    "CVE-2025-47912",
    "CVE-2025-52881",
    "CVE-2025-55131",
    "CVE-2025-58183",
    "CVE-2025-58188",
    "CVE-2025-58190",
    "CVE-2025-5991",
    "CVE-2025-6052",
    "CVE-2025-61726",
    "CVE-2025-61727",
    "CVE-2025-62518",
    "CVE-2025-64329",
    "CVE-2025-65637",
    "CVE-2026-0988",
    "CVE-2026-0989",
    "CVE-2026-0990",
    "CVE-2026-0992",
    "CVE-2026-1484",
    "CVE-2026-1485",
    "CVE-2026-1757",
    "CVE-2026-23950",
    "CVE-2026-24842",
)


def _description_from_cve(cve: CVE) -> str:
    """Use comment_zero when non-empty, else description."""
    if cve.comment_zero and cve.comment_zero.strip():
        return cve.comment_zero.strip()
    return (cve.description or "").strip()


def _components_list(cve: CVE) -> list[str]:
    """Return list of component name strings from cache."""
    raw = cve.components or []
    out = []
    for x in raw:
        if isinstance(x, str):
            out.append(x.strip())
        elif isinstance(x, dict) and "name" in x:
            out.append(str(x["name"]).strip())
        else:
            out.append(str(x).strip())
    return [c for c in out if c]


def _load_qualifying_cves(
    cve_id_filter: set[str] | None = None,
) -> list[tuple[str, CVE]]:
    """Load CVEs from osidb_cache that have title, body, and components."""
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

        title = (cve.title or "").strip()
        body = _description_from_cve(cve)
        components = _components_list(cve)

        if not title or not body or not components:
            continue
        qualifying.append((cve_id, cve))

    return qualifying


def _build_cases(
    sample_size: int | None = None,
    seed: int = SAMPLE_SEED,
    cve_id_filter: set[str] | None = None,
) -> list["SuggestAffectedComponentsCase"]:
    """Build cases from osidb_cache; optionally sample N."""
    qualifying = _load_qualifying_cves(cve_id_filter=cve_id_filter)
    cases = []

    for cve_id, cve in qualifying:
        expected_components = _components_list(cve)
        case = SuggestAffectedComponentsCase(
            name=f"suggest-affected-components-{cve_id}",
            inputs=cve_id,
            expected_output=expected_components,
            metadata={"cve_id": cve_id},
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


class SuggestAffectedComponentsCase(Case):
    """Evaluation case: inputs = cve_id, expected_output = list of component names."""

    inputs: str  # cve_id
    expected_output: list[str]


def _normalized_component_sets(names: list[str]) -> set[str]:
    """Normalize component names for comparison (lowercase, strip)."""
    return {n.lower().strip() for n in names if n and isinstance(n, str)}


class ComponentsOverlapEvaluator(Evaluator[str, SuggestAffectedComponentsModel]):
    """Scores overlap between suggested and expected components.

    Prefers identical matches over partial overlap: exact set equality yields 1.0,
    while partial overlap (e.g. expected ['python','cpython'], got ['python']) scores
    lower using Jaccard on exact set intersection.
    """

    def evaluate(
        self, ctx: EvaluatorContext[str, SuggestAffectedComponentsModel]
    ) -> float:
        expected = cast(list[str], ctx.expected_output or [])
        suggested = getattr(ctx.output, "components", None) or []
        exp_set = _normalized_component_sets(expected)
        got_set = _normalized_component_sets(suggested)

        # Empty expected (edge case: insufficient data to infer): full score if
        # model also returns empty (correctly refrains from guessing), else 0.
        if not exp_set:
            return 1.0 if not got_set else 0.0

        # Identical match: full score
        if exp_set == got_set:
            return reflect_confidence(ctx, 1.0)

        # Partial overlap: use exact set intersection for Jaccard so we
        # differentiate identical vs partial (e.g. got ['python'] when
        # expected ['python','cpython'] scores < 1.0)
        inter = len(exp_set & got_set)
        union = len(exp_set | got_set)
        jaccard = inter / union if union else 0.0

        primary_bonus = (
            1.0
            if (expected and exp_set and expected[0].lower().strip() in got_set)
            else 0.0
        )

        score = 0.5 * jaccard + 0.5 * primary_bonus
        return reflect_confidence(ctx, score)


class TestStripComponentPrefixFromTitle:
    """Unit tests for _strip_component_prefix_from_title helper."""

    def test_strips_simple_component_prefix(self) -> None:
        """Title starting with 'Component: ' should strip to rest."""
        assert (
            _strip_component_prefix_from_title("kernel: buffer overflow")
            == "buffer overflow"
        )

    def test_does_not_strip_mid_sentence_colon(self) -> None:
        """Colon mid-sentence (e.g. 'Audio/Video: Playback') should not strip."""
        assert (
            _strip_component_prefix_from_title(
                "Use-after-free in the Audio/Video: Playback"
            )
            is None
        )

    def test_does_not_strip_dom_window_style(self) -> None:
        """'DOM: Window' style (colon after slash) - pattern not at start."""
        assert (
            _strip_component_prefix_from_title(
                "Use-after-free in the DOM: Window component"
            )
            is None
        )

    def test_empty_title_returns_none(self) -> None:
        assert _strip_component_prefix_from_title("") is None

    def test_no_colon_returns_none(self) -> None:
        assert _strip_component_prefix_from_title("No colon here") is None


async def suggest_affected_components(cve_id: CVEID) -> SuggestAffectedComponentsModel:
    """Run SuggestAffectedComponents for the given CVE (no static_context)."""
    feature = SuggestAffectedComponents(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


evals = [
    FeatureMetricsEvaluator(),
    ToolsUsedEvaluator(),
    ComponentsOverlapEvaluator(),
]

pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest.fixture(scope="session")
def suggest_affected_components_cases(request):
    """Build cases from osidb_cache."""
    sample_size = request.config.getoption("sample", default=None)
    if sample_size is None:
        env_val = os.getenv("AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE")
        if env_val:
            try:
                sample_size = int(env_val)
            except ValueError:
                sample_size = None

    raw = os.getenv("AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_CVE_IDS", "").strip()
    if raw:
        cve_id_filter = {cve_id.strip() for cve_id in raw.split(",") if cve_id.strip()}
    else:
        cve_id_filter = set(DEFAULT_CVE_IDS) if DEFAULT_CVE_IDS else None
    return _build_cases(
        sample_size=sample_size,
        seed=SAMPLE_SEED,
        cve_id_filter=cve_id_filter,
    )


async def test_eval_suggest_affected_components(suggest_affected_components_cases):
    """Suggest affected components evaluation entry point."""
    if not suggest_affected_components_cases:
        pytest.skip(
            "No qualifying cases in osidb_cache (need title, description, components). "
            "Set OSIDB_CACHE_DIR if needed."
        )
    await run_evaluation(
        suggest_affected_components_cases,
        evals,
        suggest_affected_components,
        agent=rh_feature_agent,
    )
