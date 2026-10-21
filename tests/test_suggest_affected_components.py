"""Offline regressions for affected-component instructions sent to the agent."""

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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "static_context",
    [
        None,
        {
            "title": "grpc-gateway: access control bypass",
            "description": "ServeMux.ServeHTTP processes X-HTTP-Method-Override.",
        },
    ],
    ids=["cve-id-only", "static-context"],
)
async def test_grpc_gateway_rule_uses_runtime_after_major_version(
    component_agent, static_context
):
    agent, run = component_agent

    await cve.SuggestAffectedComponents(agent).exec(
        "CVE-2026-37236", static_context=static_context
    )

    run.assert_awaited_once()
    prompt = run.await_args.args[0]
    target = "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
    rule = next(line for line in prompt.splitlines() if target in line)
    assert f"use '{target}' as the affected component" in rule
    assert "instead of the module root" in rule
    assert "github.com/grpc-ecosystem/grpc-gateway/runtime/v2" not in prompt
    assert "github.com/grpc-ecosystem/grpc-gateway/v2/v2/runtime" not in prompt


@pytest.mark.asyncio
async def test_additional_module_extension_reaches_agent_prompt(
    component_agent, monkeypatch
):
    agent, run = component_agent
    monkeypatch.setitem(
        cve.GO_MODULE_PACKAGE_EXTENSIONS,
        "example.org/project/v7",
        "client/transport",
    )

    await cve.SuggestAffectedComponents(agent).exec("CVE-2026-37236")

    run.assert_awaited_once()
    prompt = run.await_args.args[0]
    # Adding a mapping must preserve the built-in rule and the complete suffix.
    for target in (
        "github.com/grpc-ecosystem/grpc-gateway/v2/runtime",
        "example.org/project/v7/client/transport",
    ):
        assert f"use '{target}' as the affected component" in prompt
    assert "example.org/project/client/transport/v7" not in prompt


@pytest.mark.asyncio
@pytest.mark.parametrize("empty_extensions", [False, True], ids=["default", "empty"])
async def test_package_extensions_preserve_general_go_identity_rules(
    component_agent, monkeypatch, empty_extensions
):
    agent, run = component_agent
    if empty_extensions:
        monkeypatch.setattr(cve, "GO_MODULE_PACKAGE_EXTENSIONS", {})

    await cve.SuggestAffectedComponents(agent).exec("CVE-2025-64329")

    run.assert_awaited_once()
    prompt = run.await_args.args[0]
    assert "github.com/containerd/containerd/v2" in prompt
    assert "golang.org/x/net/html" in prompt
    assert "github.com/external-secrets/external-secrets" in prompt
    assert "Never shorten to just the repo name" in prompt
    assert "collapse an affected package path to its module root" in prompt
    assert "strip /v2, /v7" in prompt
    assert "do not invent a version segment from a release version alone" in prompt
    assert "list each distinct path separately" in prompt
    assert "keep the full stdlib path" in prompt
    if empty_extensions:
        assert "github.com/grpc-ecosystem/grpc-gateway/v2/runtime" not in prompt
