"""Offline tests of fixture-derived component cases and their exact evaluator."""

import json
from pathlib import Path

import pytest
from pydantic_evals.evaluators import EvaluatorContext
from pydantic_evals.otel import SpanTree

from aegis_ai.features.cve.data_models import SuggestAffectedComponentsModel
from aegis_ai.toolsets.tools.osidb import CVE
from evals.features.cve import test_suggest_affected_components as component_evals

CACHE_DIR = Path(__file__).parents[1] / "evals/osidb_cache"
OAUTH2_CVE_ID = "CVE-2026-40575"


@pytest.fixture
def oauth2_case(monkeypatch):
    monkeypatch.setattr(component_evals, "OSIDB_CACHE_DIR", CACHE_DIR)
    (case,) = component_evals._build_cases(cve_id_filter={OAUTH2_CVE_ID})
    return case


@pytest.mark.parametrize("cve_id", component_evals.GO_MODULE_IDENTITY_CVE_IDS)
def test_go_case_expectations_come_directly_from_cache(monkeypatch, cve_id):
    monkeypatch.setattr(component_evals, "OSIDB_CACHE_DIR", CACHE_DIR)
    cached = json.loads((CACHE_DIR / f"{cve_id}.json").read_text())

    (case,) = component_evals._build_cases(cve_id_filter={cve_id})

    assert case.inputs == cve_id
    assert case.expected_output == cached["components"]
    assert case.metadata is not None
    assert case.metadata["require_exact_components"] is True
    assert any(
        isinstance(evaluator, component_evals.ExactComponentsEvaluator)
        for evaluator in case.evaluators
    )


def test_oauth2_case_uses_reviewed_osidb_pair(oauth2_case):
    assert oauth2_case.expected_output == [
        "oauth2-proxy",
        "github.com/oauth2-proxy/oauth2-proxy",
    ]


def test_case_builder_does_not_override_loaded_osidb_components(monkeypatch):
    # Simulate an OSIDB review revision in memory. A per-CVE curated override
    # must not silently restore the current pair or synthesize a /v7 identity.
    cached = CVE.model_validate_json((CACHE_DIR / f"{OAUTH2_CVE_ID}.json").read_text())
    revised = cached.model_copy(update={"components": [cached.components[0]]})
    monkeypatch.setattr(
        component_evals,
        "_load_qualifying_cves",
        lambda **kwargs: [(OAUTH2_CVE_ID, revised)],
    )

    (case,) = component_evals._build_cases(cve_id_filter={OAUTH2_CVE_ID})

    assert case.expected_output == revised.components
    assert case.inputs == OAUTH2_CVE_ID


@pytest.mark.parametrize(
    ("variant", "accepted"),
    [
        ("unchanged", True),
        ("reordered", True),
        ("forced-v7-only", False),
        ("forced-v7-with-distro", False),
        ("missing-distro", False),
        ("missing-module", False),
        ("extra-v7", False),
        ("duplicate", False),
        ("duplicate-replaces-module", False),
        ("empty", False),
    ],
)
def test_exact_evaluator_requires_complete_osidb_identities(
    oauth2_case, variant, accepted
):
    expected = oauth2_case.expected_output
    distro, module = expected
    suggestions = {
        "unchanged": expected,
        "reordered": list(reversed(expected)),
        "forced-v7-only": [f"{module}/v7"],
        "forced-v7-with-distro": [distro, f"{module}/v7"],
        "missing-distro": [module],
        "missing-module": [distro],
        "extra-v7": [*expected, f"{module}/v7"],
        "duplicate": [*expected, distro],
        "duplicate-replaces-module": [distro, distro],
        "empty": [],
    }
    output = SuggestAffectedComponentsModel(
        cve_id=OAUTH2_CVE_ID,
        components=suggestions[variant],
        explanation="Offline evaluator input, not an inferred model response.",
        confidence=1.0,
        data_quality=1.0,
        disclaimer=SuggestAffectedComponentsModel.model_json_schema()["properties"][
            "disclaimer"
        ]["const"],
    )
    ctx = EvaluatorContext(
        name=oauth2_case.name,
        inputs=oauth2_case.inputs,
        metadata=oauth2_case.metadata,
        expected_output=expected,
        output=output,
        duration=0.0,
        _span_tree=SpanTree(),
        attributes={},
        metrics={},
    )

    result = component_evals.ExactComponentsEvaluator().evaluate(ctx)

    assert result.value is accepted
    if not accepted:
        assert result.reason is not None
        assert "got " in result.reason
        assert "expected " in result.reason
