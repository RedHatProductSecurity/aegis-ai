"""
Component Intelligence evaluation suite.

Uses osidb_cache CVE data as (title, description) inputs with expected components.
Runnable independently: pytest evals/features/component/test_component_intelligence.py
Optional sampling to limit Gemini calls: --sample N or COMPONENT_INTEL_EVAL_SAMPLE=N
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
from aegis_ai.features.component import ComponentIntelligence
from aegis_ai.features.component.data_models import ComponentIntelligenceModel
from aegis_ai.toolsets.tools.osidb import CVE

from evals.features.common import (
    FeatureMetricsEvaluator,
    reflect_confidence,
    run_evaluation,
)
from evals.utils.osidb_cache import OSIDB_CACHE_DIR

logger = logging.getLogger(__name__)

# Fixed seed for reproducible sampling when --sample N is used
COMPONENT_INTEL_EVAL_SAMPLE_SEED = int(
    os.getenv("COMPONENT_INTEL_EVAL_SAMPLE_SEED", "42")
)

# Optional cap on description length (0 = no cap). Reduces input tokens when set.
COMPONENT_INTEL_EVAL_MAX_DESCRIPTION_CHARS = int(
    os.getenv("COMPONENT_INTEL_EVAL_MAX_DESCRIPTION_CHARS", "0")
)
# Optional: skip cases whose description is longer than this (0 = don't skip). Reduces runs on very long inputs.
COMPONENT_INTEL_EVAL_SKIP_DESCRIPTION_LONGER_THAN = int(
    os.getenv("COMPONENT_INTEL_EVAL_SKIP_DESCRIPTION_LONGER_THAN", "0")
)


def _normalize_title(title: str) -> str:
    """Strip leading 'prefix:' from title so the component name is not given away."""
    if not title or ":" not in title:
        return title.strip()
    rest = title.split(":", 1)[-1].strip()
    return rest if rest else title.strip()


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
    """Load CVEs from osidb_cache that have title, body, and components. Returns (cve_id, CVE).
    If cve_id_filter is set, only include those CVE IDs."""
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


def _build_component_intelligence_cases(
    sample_size: int | None = None,
    seed: int = COMPONENT_INTEL_EVAL_SAMPLE_SEED,
    cve_id_filter: set[str] | None = None,
) -> list["ComponentIntelligenceCase"]:
    """Build ComponentIntelligenceCase list from osidb_cache; optionally sample N with fixed seed.
    If cve_id_filter is set, only load those CVE IDs (e.g. COMPONENT_INTEL_EVAL_CVE_IDS)."""
    qualifying = _load_qualifying_cves(cve_id_filter=cve_id_filter)
    cases = []

    for cve_id, cve in qualifying:
        title_raw = (cve.title or "").strip()
        title_normalized = _normalize_title(title_raw)
        description = _description_from_cve(cve)

        if (
            COMPONENT_INTEL_EVAL_SKIP_DESCRIPTION_LONGER_THAN
            and len(description) > COMPONENT_INTEL_EVAL_SKIP_DESCRIPTION_LONGER_THAN
        ):
            continue
        if (
            COMPONENT_INTEL_EVAL_MAX_DESCRIPTION_CHARS
            and len(description) > COMPONENT_INTEL_EVAL_MAX_DESCRIPTION_CHARS
        ):
            description = (
                description[:COMPONENT_INTEL_EVAL_MAX_DESCRIPTION_CHARS].rstrip()
                + " […]"
            )

        expected_components = _components_list(cve)

        case = ComponentIntelligenceCase(
            name=f"component-intelligence-from-{cve_id}",
            inputs={
                "title": title_normalized,
                "description": description,
                "cve_id": cve_id,
            },
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


class ComponentIntelligenceCase(Case):
    """Evaluation case: inputs = {title, description, cve_id}, expected_output = list of component names."""

    inputs: dict[str, str]  # title (normalized), description, cve_id (for OSIDB lookup)
    expected_output: list[str]  # expected component names


def _normalized_component_sets(names: list[str]) -> set[str]:
    """Normalize component names for comparison (lowercase, strip)."""
    return {n.lower().strip() for n in names if n and isinstance(n, str)}


def _component_match(exp: str, got_set: set[str]) -> bool:
    """True if expected component is in got_set or contained in a got name (e.g. kernel vs linux kernel)."""
    exp_n = exp.lower().strip()
    if exp_n in got_set:
        return True
    for g in got_set:
        if exp_n in g or g in exp_n:
            return True
    return False


class ComponentsOverlapEvaluator(Evaluator[dict[str, str], ComponentIntelligenceModel]):
    """Scores overlap between suggested and expected components (Jaccard + primary present)."""

    def evaluate(
        self, ctx: EvaluatorContext[dict[str, str], ComponentIntelligenceModel]
    ) -> float:
        # expected_output is list[str] for ComponentIntelligenceCase; context is generic
        expected = cast(list[str], ctx.expected_output or [])
        suggested = getattr(ctx.output, "components", None) or []
        exp_set = _normalized_component_sets(expected)
        got_set = _normalized_component_sets(suggested)

        if not exp_set:
            return 1.0

        # Jaccard: count matches (exact or substring) so e.g. "kernel" matches "linux kernel"
        inter = sum(1 for e in exp_set if _component_match(e, got_set))
        union = len(exp_set | got_set)
        jaccard = inter / union if union else 0.0

        # Primary component present (first expected matches some suggested)
        primary_bonus = (
            1.0 if (expected and _component_match(expected[0], got_set)) else 0.0
        )

        # Combine: 50% Jaccard, 50% primary
        score = 0.5 * jaccard + 0.5 * primary_bonus
        return reflect_confidence(ctx, score)


async def component_intelligence_from_title_description(
    inputs: dict[str, str],
) -> ComponentIntelligenceModel:
    """Run Component Intelligence with title + description (and cve_id when present) from the case."""
    feature = ComponentIntelligence(rh_feature_agent)
    result = await feature.exec(
        title=inputs.get("title") or "",
        description=inputs.get("description") or "",
        cve_id=inputs.get("cve_id") or None,
    )
    return result.output


# Evaluators: no ToolsUsedEvaluator (component intelligence does not use osidb_tool the same way)
evals = [
    FeatureMetricsEvaluator(),
    ComponentsOverlapEvaluator(),
]

pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest.fixture(scope="session")
def component_intelligence_cases(component_intel_sample_size, component_intel_cve_ids):
    """Build cases from osidb_cache; apply --sample / COMPONENT_INTEL_EVAL_CVE_IDS if set."""
    return _build_component_intelligence_cases(
        sample_size=component_intel_sample_size,
        seed=COMPONENT_INTEL_EVAL_SAMPLE_SEED,
        cve_id_filter=component_intel_cve_ids,
    )


async def test_eval_component_intelligence(component_intelligence_cases):
    """Component intelligence evaluation entry point. Run with optional --sample N."""
    if not component_intelligence_cases:
        pytest.skip(
            "No qualifying cases in osidb_cache (need title, comment_zero or description, components). "
            "Set OSIDB_CACHE_DIR if needed."
        )
    # Run with max_concurrency=1 to avoid asyncio/anyio "exit cancel scope in different task" errors
    # when MCP or other tools use cancel scopes across concurrent agent runs.
    await run_evaluation(
        component_intelligence_cases,
        evals,
        component_intelligence_from_title_description,
        max_concurrency=1,
    )
