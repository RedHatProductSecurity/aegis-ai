"""Offline regressions for affected-component instructions sent to the agent."""

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel

from aegis_ai.features import cve
from aegis_ai.features.cve.data_models import SuggestAffectedComponentsModel
from aegis_ai.prompt import AegisPrompt


@pytest.fixture
def component_agent(monkeypatch):
    # Exercise exec(), guarded_run(), and prompt serialization with an offline model.
    schema = SuggestAffectedComponentsModel.model_json_schema()
    model = TestModel(
        custom_output_args={
            "cve_id": "CVE-2026-37236",
            "components": [],
            "explanation": "Offline response; only the outgoing prompt is under test.",
            "data_quality": 0.0,
            "confidence": 0.0,
            "disclaimer": schema["properties"]["disclaimer"]["const"],
        }
    )
    agent = Agent(model, output_type=SuggestAffectedComponentsModel)
    run = AsyncMock(wraps=agent.run)
    monkeypatch.setattr(agent, "run", run)
    monkeypatch.setattr(AegisPrompt, "is_safe", AsyncMock(return_value=True))
    return agent, run


GRPC_GATEWAY_STATIC_CONTEXT = {
    "title": "grpc-gateway: Access control bypass via X-HTTP-Method-Override header",
    "comment_zero": (
        "grpc-gateway v2.28.0 is vulnerable to Incorrect Access Control. The "
        "application processes the X-HTTP-Method-Override header in "
        "ServeMux.ServeHTTP without restricting allowed methods."
    ),
    "components": [
        "github.com/grpc-ecosystem/grpc-gateway",
        "github.com/grpc-ecosystem/grpc-gateway/v2",
    ],
}

MONGO_DRIVER_STATIC_CONTEXT = {
    "title": (
        "MongoDB Go Driver: Write redirection via unvalidated database name in "
        "Client.BulkWrite"
    ),
    "comment_zero": (
        "The MongoDB Go Driver's client-level bulk write operation may accept a "
        "caller-supplied database name containing a reserved separator character "
        "without escaping it before the name is used to build the target "
        "namespace for the operation. Only the Client.BulkWrite API is affected."
    ),
    "components": ["go.mongodb.org/mongo-driver/v2"],
}

OAUTH2_PROXY_STATIC_CONTEXT = json.loads(
    (Path(__file__).parents[1] / "evals/osidb_cache/CVE-2026-40575.json").read_text()
)


@pytest.mark.asyncio
async def test_general_go_identity_rules_reach_agent_prompt(component_agent):
    agent, run = component_agent

    await cve.SuggestAffectedComponents(agent).exec("CVE-2025-64329")

    run.assert_awaited_once()
    prompt = run.await_args.args[0]
    assert "OSIDB component naming is the source of ground truth" in prompt
    assert "OSIDB remains authoritative for output component naming" in prompt
    assert "github.com/containerd/containerd/v2" in prompt
    assert "github.com/go-acme/lego/v4" in prompt
    assert "golang.org/x/net/html" in prompt
    assert "golang.org/x/oauth2/jws" in prompt
    assert "Preserve major-version segments when" in prompt
    assert "do not invent a version segment from a release version alone" in prompt
    assert "rather than generating aliases speculatively" in prompt
    assert "keep the full stdlib path" in prompt


@pytest.mark.asyncio
async def test_semantic_import_versioning_rule_reaches_agent_prompt(component_agent):
    agent, run = component_agent

    await cve.SuggestAffectedComponents(agent).exec("CVE-2025-64329")

    run.assert_awaited_once()
    prompt = run.await_args.args[0]
    assert "Go modules follow Semantic Import Versioning" in prompt
    assert "list the module path for every affected major version" in prompt
    assert "github.com/grpc-ecosystem/grpc-gateway/v2" in prompt
    assert "go.mongodb.org/mongo-driver/v2" in prompt


@pytest.mark.asyncio
async def test_upstream_registry_identity_does_not_override_osidb(component_agent):
    agent, run = component_agent

    await cve.SuggestAffectedComponents(agent).exec(
        "CVE-2026-40575", static_context=OAUTH2_PROXY_STATIC_CONTEXT
    )

    prompt = run.await_args.args[0]
    assert "'oauth2-proxy' and 'github.com/oauth2-proxy/oauth2-proxy'" in prompt
    assert "including distribution package names when OSIDB records them" in prompt
    assert "does not exclude multiple OSIDB component names" in prompt
    assert "Do not add or strip version segments solely" in prompt
    # These old absolutes contradicted the cached OSIDB identities, even when
    # an upstream advisory names only the /v7 registry artifact.
    for conflicting_rule in (
        "always use the full affected module or package path",
        "github.com/oauth2-proxy/oauth2-proxy/v7",
        "full module path (see above) takes precedence",
        "GHSA package name is the canonical registry identifier",
        "strong evidence that no other components should be listed",
    ):
        assert conflicting_rule not in prompt


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cve_id", "static_context", "comment_marker"),
    [
        pytest.param(
            "CVE-2026-37236",
            GRPC_GATEWAY_STATIC_CONTEXT,
            "ServeMux.ServeHTTP",
            id="grpc-gateway",
        ),
        pytest.param(
            "CVE-2026-81521",
            MONGO_DRIVER_STATIC_CONTEXT,
            "caller-supplied database name",
            id="mongo-driver",
        ),
        pytest.param(
            "CVE-2026-40575",
            OAUTH2_PROXY_STATIC_CONTEXT,
            "X-Forwarded-Uri",
            id="oauth2-proxy",
        ),
    ],
)
async def test_go_module_cve_prompt_carries_context_and_identity_rules(
    component_agent, cve_id, static_context, comment_marker
):
    agent, run = component_agent

    await cve.SuggestAffectedComponents(agent).exec(
        cve_id, static_context=static_context
    )

    run.assert_awaited_once()
    prompt = run.await_args.args[0]
    assert static_context["title"] in prompt
    assert comment_marker in prompt
    assert "preserve each distinct affected component identity used by OSIDB" in prompt
    assert "Do not collapse distinct OSIDB component names" in prompt
    assert "or expand a module root into a package subpath" in prompt


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cve_id", "static_context"),
    [
        pytest.param("CVE-2026-37236", GRPC_GATEWAY_STATIC_CONTEXT, id="grpc-gateway"),
        pytest.param("CVE-2026-81521", MONGO_DRIVER_STATIC_CONTEXT, id="mongo-driver"),
        pytest.param("CVE-2026-40575", OAUTH2_PROXY_STATIC_CONTEXT, id="oauth2-proxy"),
    ],
)
async def test_ground_truth_components_withheld_from_agent_prompt(
    component_agent, cve_id, static_context
):
    agent, run = component_agent
    # Sentinels detect field leakage even when an identity already appears in
    # the CVE prose or in a general naming example in the instructions.
    static_context = {
        **static_context,
        "components": [*static_context["components"], "withheld-component-marker"],
        "affects": [{"ps_component": "withheld-affect-marker"}],
    }

    await cve.SuggestAffectedComponents(agent).exec(
        cve_id, static_context=static_context
    )

    run.assert_awaited_once()
    prompt = run.await_args.args[0]
    assert "withheld-component-marker" not in prompt
    assert "withheld-affect-marker" not in prompt
    context = prompt.split("Context:\n", 1)[1].split("Format:", 1)[0]
    assert "components=" not in context
    assert "affects=" not in context
    assert static_context["title"] in context
    deps = run.await_args.kwargs["deps"]
    assert set(deps.exclude_osidb_fields) == {"components", "affects"}
