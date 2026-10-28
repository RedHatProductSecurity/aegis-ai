from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from fastapi import HTTPException
from fastapi.testclient import TestClient

from aegis_ai import get_settings
from aegis_ai.agents import public_feature_agent, rh_feature_agent
from aegis_ai.features import Feature
from aegis_ai.features import component as component_features
from aegis_ai.features import cve as cve_features
from aegis_ai.features.component.data_models import ComponentIntelligenceModel
from aegis_ai.features.cve.data_models import (
    SuggestAffectedComponentsModel,
    SuggestDescriptionModel,
    SuggestStatementModel,
)
from aegis_ai.toolsets.tools.osidb.osidb_client import (
    OSIDBFlawNotFoundError,
    OSIDBUnauthorizedError,
)
from aegis_ai_web.src.main import (
    DEFAULT_CVE_FEATURES,
    _resolve_agent,
    app,
    cve_feature_registry,
    llm_agent,
)

# Create a TestClient instance based on your FastAPI app
client = TestClient(app)


def test_cve_analysis_osidb_unauthorized_returns_401():
    """
    OSIDB HTTP 401 (e.g. /auth/token or flaw API) maps to API 401, not 500.
    """
    with patch.object(
        cve_features.SuggestCWE,
        "exec",
        new_callable=AsyncMock,
        side_effect=OSIDBUnauthorizedError(),
    ):
        response = client.get(
            "/api/v1/analysis/cve",
            params={
                "feature": "suggest-cwe",
                "cve_id": "CVE-2026-4404",
            },
        )
    assert response.status_code == 401
    assert "401" in response.json()["detail"] or "OSIDB" in response.json()["detail"]


def test_cve_analysis_osidb_flaw_not_found_returns_404():
    """
    Missing OSIDB flaw (HTTP 404) maps to API 404 with a clear message, not 500.
    """
    with patch.object(
        cve_features.SuggestCWE,
        "exec",
        new_callable=AsyncMock,
        side_effect=OSIDBFlawNotFoundError("CVE-2025-59536"),
    ):
        response = client.get(
            "/api/v1/analysis/cve",
            params={
                "feature": "suggest-cwe",
                "cve_id": "CVE-2025-59536",
            },
        )
    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "CVE-2025-59536" in detail
    assert "OSIDB" in detail


def test_component_analysis_osidb_unauthorized_returns_401():
    """Component analysis maps OSIDBUnauthorizedError to HTTP 401 like CVE analysis."""
    with patch.object(
        component_features.ComponentIntelligence,
        "exec",
        new_callable=AsyncMock,
        side_effect=OSIDBUnauthorizedError(),
    ):
        response = client.get(
            "/api/v1/analysis/component",
            params={
                "feature": "component-intelligence",
                "component_name": "foo",
            },
        )
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert "401" in detail or "OSIDB" in detail


def test_read_root():
    """
    Test the root endpoint to ensure it returns a 200 OK status.
    """
    response = client.get("/")
    assert response.status_code == 200


def test_yaml_openapi():
    """
    Test the root endpoint to ensure it returns a 200 OK status.
    """
    response = client.get("/openapi.yml")
    assert response.status_code == 200
    assert "application/vnd.oai.openapi" in response.headers["content-type"]
    try:
        openapi_spec = yaml.safe_load(response.text)
    except yaml.YAMLError:
        assert False, "Response is not valid YAML"

    assert isinstance(openapi_spec, dict)
    assert "openapi" in openapi_spec
    assert "info" in openapi_spec
    assert "paths" in openapi_spec

    assert openapi_spec["info"]["title"] == "Aegis REST-API"


@pytest.mark.parametrize(
    "invalid_json_content,description",
    [
        ("invalid json content", "completely invalid JSON"),
        ('{"cve_id": "CVE-2025-12345"', "malformed JSON (missing closing brace)"),
        ("", "empty body"),
    ],
)
def test_invalid_json_request_body(invalid_json_content, description):
    """
    Test that invalid JSON in request body returns 422 with proper error detail
    instead of leaking a full traceback.
    """
    response = client.post(
        "/api/v1/analysis/cve/suggest-impact",
        content=invalid_json_content,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "detail" in response.json()
    assert "Traceback" not in response.text
    assert "stack" not in response.text


def test_missing_cve_id_field():
    """
    Test that missing 'cve_id' field in request body returns 422 with proper error detail
    instead of leaking a full traceback.
    """
    response = client.post(
        "/api/v1/analysis/cve/suggest-impact",
        json={},  # Empty JSON body - missing 'cve_id' field
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "detail" in response.json()
    assert "Traceback" not in response.text
    assert "stack" not in response.text


def test_empty_cve_id():
    """
    Empty 'cve_id' is rejected by Pydantic's CVEID regex and returns 422
    (FastAPI's standard for request-validation errors), consistent with the
    multi-analysis endpoint.
    """
    response = client.post(
        "/api/v1/analysis/cve/suggest-impact",
        json={"cve_id": ""},
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_invalid_utf8_encoding():
    """
    Test that invalid UTF-8 encoding in request body returns an error
    instead of leaking a full traceback.

    Note: This test sends raw bytes with invalid UTF-8. FastAPI catches
    the error during body parsing and returns 422.
    """
    # Create invalid UTF-8 bytes (invalid continuation byte \x80)
    # This simulates the curl example: curl -d $'{\x80'
    invalid_utf8 = b"{\x80"
    response = client.post(
        "/api/v1/analysis/cve/suggest-impact",
        content=invalid_utf8,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code in (400, 422)
    assert "detail" in response.json()
    assert "Traceback" not in response.text
    assert "stack" not in response.text


def test_component_intelligence_endpoint_uses_component_name_context():
    """
    Test that component-intelligence endpoint succeeds when context has component_name
    only (no cve_id). Regression test for fix: cve_id not in context for
    component_intelligence.
    """
    mock_output = ComponentIntelligenceModel(
        component_name="curl",
        component_latest_version="8.10.0",
        component_purl="pkg:generic/curl@8.10.0",
        website_url="https://curl.se",
        repo_url="https://github.com/curl/curl",
        popularity_score=1,
        stability_score=1,
        recent_news="Recent release.",
        active_contributors="Core team.",
        security_information="No critical issues.",
        further_learning="See docs.",
        explanation="Test mock.",
        data_quality=1.0,
        confidence=0.95,
        tools_used=[],
        disclaimer="This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert.",
    )
    mock_result = MagicMock()
    mock_result.output = mock_output
    mock_result._state = MagicMock()
    mock_result._state.usage = MagicMock()
    mock_result._state.usage.input_tokens = 0

    with patch(
        "aegis_ai.features.Feature._run",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        response = client.get(
            "/api/v1/analysis/component",
            params={"feature": "component-intelligence", "component_name": "curl"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["component_name"] == "curl"
    assert "popularity_score" in data


def test_suggest_affected_components_endpoint():
    """Test that suggest-affected-components CVE endpoint exists and returns full response shape."""
    mock_output = SuggestAffectedComponentsModel(
        cve_id="CVE-2024-1234",
        components=["kernel", "linux-kernel"],
        explanation="Mock explanation.",
        data_quality=1.0,
        confidence=0.95,
        tools_used=["osidb_tool"],
        disclaimer=(
            "This response was generated by Aegis AI "
            "(https://github.com/RedHatProductSecurity/aegis-ai) using generative AI "
            "for informational purposes. All findings should be validated by a human expert."
        ),
    )
    mock_result = MagicMock()
    mock_result.output = mock_output
    mock_result._state = MagicMock()
    mock_result._state.usage = MagicMock()
    mock_result._state.usage.input_tokens = 0

    with patch(
        "aegis_ai.features.Feature._run",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        response = client.get(
            "/api/v1/analysis/cve",
            params={
                "feature": "suggest-affected-components",
                "cve_id": "CVE-2024-1234",
            },
        )
    assert response.status_code == 200
    data = response.json()

    # Core fields
    assert data["cve_id"] == mock_output.cve_id
    assert data["components"] == mock_output.components

    # Shape / type validation for additional fields
    assert "explanation" in data
    assert isinstance(data["explanation"], str)

    assert "confidence" in data
    assert isinstance(data["confidence"], (float, int))

    assert "tools_used" in data
    assert isinstance(data["tools_used"], list)

    assert "disclaimer" in data
    assert isinstance(data["disclaimer"], str)


def test_suggest_affected_components_post_endpoint():
    """Test that suggest-affected-components POST endpoint works with static context."""
    mock_output = SuggestAffectedComponentsModel(
        cve_id="CVE-2024-1234",
        components=["kernel"],
        explanation="Inferred from title and description.",
        data_quality=0.85,
        confidence=0.90,
        tools_used=["osidb_tool"],
        disclaimer=(
            "This response was generated by Aegis AI "
            "(https://github.com/RedHatProductSecurity/aegis-ai) using generative AI "
            "for informational purposes. All findings should be validated by a human expert."
        ),
    )
    mock_result = MagicMock()
    mock_result.output = mock_output
    mock_result._state = MagicMock()
    mock_result._state.usage = MagicMock()
    mock_result._state.usage.input_tokens = 0

    with patch(
        "aegis_ai.features.Feature._run",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        response = client.post(
            "/api/v1/analysis/cve/suggest-affected-components",
            json={
                "cve_id": "CVE-2024-1234",
                "title": "kernel: buffer overflow in net subsystem",
                "comment_zero": "A buffer overflow was found in the Linux kernel.",
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["cve_id"] == "CVE-2024-1234"
    assert data["components"] == ["kernel"]
    assert isinstance(data["explanation"], str)


DISCLAIMER = (
    "This response was generated by Aegis AI "
    "(https://github.com/RedHatProductSecurity/aegis-ai) using generative AI "
    "for informational purposes. All findings should be validated by a human expert."
)


def _make_mock_result(output):
    """Build a MagicMock that looks like pydantic-ai's AgentRunResult."""
    mock_result = MagicMock()
    mock_result.output = output
    mock_result._state = MagicMock()
    mock_result._state.usage = MagicMock()
    mock_result._state.usage.input_tokens = 0
    return mock_result


def _make_sac_output(cve_id="CVE-2024-1234"):
    return SuggestAffectedComponentsModel(
        cve_id=cve_id,
        components=["kernel"],
        explanation="Mock.",
        data_quality=1.0,
        confidence=0.9,
        tools_used=[],
        disclaimer=DISCLAIMER,
    )


@contextmanager
def _patch_all_cve_feature_execs(mock_result):
    """Patch exec() on all CVE feature classes and yield the execution mocks."""
    from contextlib import ExitStack

    with ExitStack() as stack:
        exec_mocks = []
        for feature_cls in cve_feature_registry.values():
            exec_mocks.append(
                stack.enter_context(
                    patch.object(
                        feature_cls,
                        "exec",
                        new_callable=AsyncMock,
                        return_value=mock_result,
                    )
                )
            )
        yield exec_mocks


def _make_steering_notes_outputs():
    components = _make_sac_output().model_copy(update={"components": ["curl"]})
    common = components.model_dump(exclude={"components", "ecosystems"})
    return {
        SuggestAffectedComponentsModel: components,
        SuggestDescriptionModel: SuggestDescriptionModel(
            **common,
            components=["curl"],
            suggested_title="Suggested public title",
            suggested_description="Suggested public description.",
        ),
        SuggestStatementModel: SuggestStatementModel(
            **common,
            title="Public title",
            description="Public description.",
            suggested_statement="Suggested public statement.",
            suggested_mitigation=None,
        ),
    }


@pytest.fixture
def recorded_cve_prompts(monkeypatch):
    """Stub only the agent: routing, enrichment, feature exec and rendering stay real."""
    monkeypatch.setattr(get_settings(), "safety_enabled", False)
    outputs = _make_steering_notes_outputs()
    prompts: list[tuple[type, str]] = []

    async def record(prompt, *, output_type, **kwargs):
        prompts.append((output_type, prompt))
        result = _make_mock_result(outputs[output_type])
        result.all_messages.return_value = []
        return result

    with patch.object(public_feature_agent, "run", side_effect=record):
        yield prompts


def _steering_notes_request_context(notes_context):
    return {
        "cve_id": "CVE-2024-1234",
        "agent": "public",
        "title": "Public title",
        "comment_zero": "Public description.",
        "statement": "Existing public statement.",
        "mitigation": "Existing public mitigation.",
        **notes_context,
    }


def _assert_enriched_steering_notes_prompts(prompts, notes):
    for model, prompt in prompts:
        context = prompt.partition("\n\nContext:\n")[2].partition("\n\nFormat:")[0]
        assert context.startswith("CVEFeatureInput(")
        if notes is None:
            assert "steering_notes=" not in context
        else:
            assert f"steering_notes={notes!r}" in context
        if model is SuggestAffectedComponentsModel:
            assert "components=" not in context
        else:
            assert "components=['curl']" in context
        if model is SuggestDescriptionModel:
            assert " title=" not in context
            assert " description=" not in context
        if model is SuggestStatementModel:
            assert " statement=" not in context
            assert " mitigation=" not in context


class TestSteeringNotesRequests:
    @pytest.mark.parametrize(
        "endpoint", ["single", "multi-inferred", "multi-explicit-sac"]
    )
    @pytest.mark.parametrize(
        "notes",
        [
            pytest.param(0, id="integer-zero"),
            pytest.param(1.5, id="float"),
            pytest.param(True, id="true"),
            pytest.param(False, id="false"),
            pytest.param([], id="empty-array"),
            pytest.param(["notes"], id="array"),
            pytest.param({}, id="empty-object"),
            pytest.param({"text": "notes"}, id="object"),
        ],
    )
    def test_invalid_notes_rejected_before_any_feature_execution(self, endpoint, notes):
        payload = _steering_notes_request_context({"steering_notes": notes})
        path = "/api/v1/analysis/cve/suggest-statement"
        if endpoint != "single":
            path = "/api/v1/analysis/cve"
            payload["features"] = ["suggest-statement"]
            if endpoint == "multi-explicit-sac":
                payload["features"].append("suggest-affected-components")

        with _patch_all_cve_feature_execs(
            _make_mock_result(_make_sac_output())
        ) as feature_execs:
            response = client.post(path, json=payload)
            assert response.status_code == 422, response.text
            for feature_exec in feature_execs:
                feature_exec.assert_not_called()

        errors = response.json()["detail"]
        assert isinstance(errors, list)
        assert len(errors) == 1
        assert errors[0]["loc"] == ["body", "steering_notes"]
        assert errors[0]["type"] == "string_type"
        assert errors[0]["input"] == notes

    @pytest.mark.parametrize("endpoint", ["single", "multi"])
    def test_notes_and_extra_context_are_preserved_without_routing_controls(
        self, endpoint
    ):
        context = {
            "cve_id": "CVE-2024-1234",
            "steering_notes": "  Internal: café — 確認 🔎\n\tCheck reproduction.\r\n  ",
            "components": ["curl"],
            "references": [
                {"url": "https://example.com/advisory", "tags": ["upstream"]}
            ],
            "extra_context": {"reproduced": False, "attempts": 0},
        }
        payload = {**context, "agent": "public"}
        path = "/api/v1/analysis/cve/suggest-affected-components"
        if endpoint == "multi":
            path = "/api/v1/analysis/cve"
            payload["features"] = ["suggest-affected-components"]

        with patch.object(
            cve_features.SuggestAffectedComponents,
            "exec",
            new_callable=AsyncMock,
            return_value=_make_mock_result(_make_sac_output()),
        ) as feature_exec:
            response = client.post(path, json=payload)

        assert response.status_code == 200, response.text
        feature_exec.assert_awaited_once_with(context["cve_id"], static_context=context)

    @pytest.mark.parametrize("openapi_path", ["/openapi.json", "/openapi.yml"])
    def test_openapi_advertises_optional_nullable_string_notes(self, openapi_path):
        response = client.get(openapi_path)
        assert response.status_code == 200
        specification = yaml.safe_load(response.text)

        for path in ("/api/v1/analysis/cve/{feature}", "/api/v1/analysis/cve"):
            request_body = specification["paths"][path]["post"]["requestBody"]
            schema_ref = request_body["content"]["application/json"]["schema"]["$ref"]
            schema_name = schema_ref.rsplit("/", 1)[1]
            request_schema = specification["components"]["schemas"][schema_name]
            notes_schema = request_schema["properties"]["steering_notes"]

            assert "steering_notes" not in request_schema.get("required", [])
            assert {option["type"] for option in notes_schema["anyOf"]} == {
                "string",
                "null",
            }


class TestSteeringNotesPromptContext:
    @pytest.mark.parametrize(
        "endpoint", ["single", "multi-inferred", "multi-explicit-sac"]
    )
    @pytest.mark.parametrize(
        "notes_context",
        [
            pytest.param({}, id="omitted"),
            pytest.param({"steering_notes": None}, id="null"),
            pytest.param({"steering_notes": ""}, id="empty"),
            pytest.param(
                {
                    "steering_notes": "  Internal: café — 確認 🔎\n\tCheck reproduction.\r\n  "
                },
                id="unicode-multiline",
            ),
        ],
    )
    def test_notes_reach_prompts_after_component_enrichment(
        self, endpoint, notes_context, recorded_cve_prompts
    ):
        payload = _steering_notes_request_context(notes_context)
        path = "/api/v1/analysis/cve/suggest-statement"
        expected_types = {SuggestAffectedComponentsModel, SuggestStatementModel}
        if endpoint != "single":
            path = "/api/v1/analysis/cve"
            payload["features"] = ["suggest-description", "suggest-statement"]
            if endpoint == "multi-explicit-sac":
                payload["features"].append("suggest-affected-components")
            expected_types.add(SuggestDescriptionModel)

        response = client.post(path, json=payload)
        assert response.status_code == 200, response.text
        if endpoint != "single":
            assert response.json()["errors"] == {}
            assert set(response.json()["results"]) == set(payload["features"])
        assert len(recorded_cve_prompts) == len(expected_types)
        assert {model for model, _ in recorded_cve_prompts} == expected_types
        assert recorded_cve_prompts[0][0] is SuggestAffectedComponentsModel
        _assert_enriched_steering_notes_prompts(
            recorded_cve_prompts, notes_context.get("steering_notes")
        )

    @pytest.mark.parametrize("endpoint", ["single", "multi"])
    def test_failed_component_inference_keeps_notes_for_requested_feature(
        self, endpoint, recorded_cve_prompts
    ):
        notes = "Internal reproduction is awaiting component confirmation."
        payload = _steering_notes_request_context({"steering_notes": notes})
        path = "/api/v1/analysis/cve/suggest-statement"
        if endpoint == "multi":
            path = "/api/v1/analysis/cve"
            payload["features"] = ["suggest-statement"]
        with patch.object(
            cve_features.SuggestAffectedComponents,
            "_run",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Component inference failed"),
        ):
            response = client.post(path, json=payload)

        assert response.status_code == 200, response.text
        if endpoint == "multi":
            assert response.json()["errors"] == {}
        assert len(recorded_cve_prompts) == 1
        model, prompt = recorded_cve_prompts[0]
        assert model is SuggestStatementModel
        context = prompt.partition("\n\nContext:\n")[2].partition("\n\nFormat:")[0]
        assert f"steering_notes={notes!r}" in context
        assert "components=" not in context


class TestCveMultiAnalysis:
    """Tests for POST /api/v1/analysis/cve (multi-feature endpoint)."""

    def test_multiple_features_succeed(self):
        mock_result = _make_mock_result(_make_sac_output())
        with _patch_all_cve_feature_execs(mock_result):
            response = client.post(
                "/api/v1/analysis/cve",
                json={
                    "cve_id": "CVE-2024-1234",
                    "features": [
                        "suggest-affected-components",
                        "suggest-cwe",
                    ],
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert "suggest-affected-components" in data["results"]
        assert "suggest-cwe" in data["results"]
        assert data["errors"] == {}

    def test_features_omitted_runs_defaults(self):
        mock_result = _make_mock_result(_make_sac_output())
        with _patch_all_cve_feature_execs(mock_result):
            response = client.post(
                "/api/v1/analysis/cve",
                json={"cve_id": "CVE-2024-1234"},
            )
        assert response.status_code == 200
        data = response.json()
        assert set(data["results"].keys()) == set(DEFAULT_CVE_FEATURES)
        assert data["errors"] == {}
        assert all(v is not None for v in data["results"].values())

    def test_empty_features_list_runs_defaults(self):
        mock_result = _make_mock_result(_make_sac_output())
        with _patch_all_cve_feature_execs(mock_result):
            response = client.post(
                "/api/v1/analysis/cve",
                json={"cve_id": "CVE-2024-1234", "features": []},
            )
        assert response.status_code == 200
        data = response.json()
        assert set(data["results"].keys()) == set(DEFAULT_CVE_FEATURES)
        assert data["errors"] == {}
        assert all(v is not None for v in data["results"].values())

    def test_partial_failure(self):
        mock_result = _make_mock_result(_make_sac_output())
        with (
            _patch_all_cve_feature_execs(mock_result),
            patch.object(
                cve_features.SuggestImpact,
                "exec",
                new_callable=AsyncMock,
                side_effect=RuntimeError("LLM timeout"),
            ),
        ):
            response = client.post(
                "/api/v1/analysis/cve",
                json={
                    "cve_id": "CVE-2024-1234",
                    "features": ["suggest-impact", "suggest-cwe"],
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["results"]["suggest-impact"] is None
        assert "suggest-impact" in data["errors"]
        assert data["errors"]["suggest-impact"]["error"] == "RuntimeError"
        assert data["results"]["suggest-cwe"] is not None
        assert "suggest-cwe" not in data["errors"]

    def test_osidb_error_mapped_per_feature(self):
        mock_result = _make_mock_result(_make_sac_output())
        with (
            _patch_all_cve_feature_execs(mock_result),
            patch.object(
                cve_features.SuggestCWE,
                "exec",
                new_callable=AsyncMock,
                side_effect=OSIDBFlawNotFoundError("CVE-2024-1234"),
            ),
        ):
            response = client.post(
                "/api/v1/analysis/cve",
                json={
                    "cve_id": "CVE-2024-1234",
                    "features": ["suggest-cwe", "identify-pii"],
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["results"]["suggest-cwe"] is None
        assert data["errors"]["suggest-cwe"]["error"] == "OSIDBFlawNotFoundError"
        assert "CVE-2024-1234" in data["errors"]["suggest-cwe"]["detail"]
        assert data["results"]["identify-pii"] is not None

    def test_invalid_feature_name(self):
        response = client.post(
            "/api/v1/analysis/cve",
            json={
                "cve_id": "CVE-2024-1234",
                "features": ["nonexistent-feature"],
            },
        )
        assert response.status_code == 422
        assert "nonexistent-feature" in response.json()["detail"]

    def test_missing_cve_id(self):
        response = client.post(
            "/api/v1/analysis/cve",
            json={"features": ["suggest-impact"]},
        )
        assert response.status_code == 422

    def test_component_inference_called_once(self):
        mock_result = _make_mock_result(_make_sac_output())
        sac_result = _make_mock_result(_make_sac_output())

        with (
            _patch_all_cve_feature_execs(mock_result),
            patch.object(
                cve_features.SuggestAffectedComponents,
                "exec",
                new_callable=AsyncMock,
                return_value=sac_result,
            ) as mock_sac_exec,
        ):
            response = client.post(
                "/api/v1/analysis/cve",
                json={
                    "cve_id": "CVE-2024-1234",
                    "features": ["suggest-impact", "suggest-cwe"],
                    "title": "kernel: buffer overflow",
                    "comment_zero": "A buffer overflow was found.",
                },
            )
        assert response.status_code == 200
        mock_sac_exec.assert_called_once()

    def test_component_inference_skipped_when_components_provided(self):
        mock_result = _make_mock_result(_make_sac_output())

        with (
            _patch_all_cve_feature_execs(mock_result),
            patch.object(
                cve_features.SuggestAffectedComponents,
                "exec",
                new_callable=AsyncMock,
            ) as mock_sac_exec,
        ):
            response = client.post(
                "/api/v1/analysis/cve",
                json={
                    "cve_id": "CVE-2024-1234",
                    "features": ["suggest-impact"],
                    "title": "kernel: buffer overflow",
                    "comment_zero": "A buffer overflow was found.",
                    "components": ["kernel"],
                },
            )
        assert response.status_code == 200
        mock_sac_exec.assert_not_called()

    def test_sac_runs_first_and_enriches_siblings(self):
        """When SAC is requested alongside other features, it runs first
        and its inferred components are available to the sibling features."""
        sac_output = _make_sac_output()
        sac_result = _make_mock_result(sac_output)

        captured_contexts: list[dict] = []

        async def _capture_exec(cve_id, *, static_context=None):
            captured_contexts.append(static_context or {})
            return _make_mock_result(_make_sac_output())

        with _patch_all_cve_feature_execs(_make_mock_result(_make_sac_output())):  # noqa: SIM117
            with patch.object(
                cve_features.SuggestAffectedComponents,
                "exec",
                new_callable=AsyncMock,
                return_value=sac_result,
            ) as mock_sac_exec:
                with patch.object(
                    cve_features.SuggestImpact,
                    "exec",
                    side_effect=_capture_exec,
                ):
                    response = client.post(
                        "/api/v1/analysis/cve",
                        json={
                            "cve_id": "CVE-2024-1234",
                            "features": [
                                "suggest-affected-components",
                                "suggest-impact",
                            ],
                            "title": "kernel: buffer overflow",
                            "comment_zero": "A buffer overflow was found.",
                        },
                    )
        assert response.status_code == 200
        data = response.json()
        assert data["results"]["suggest-affected-components"] is not None
        assert data["results"]["suggest-impact"] is not None
        mock_sac_exec.assert_called_once()
        assert captured_contexts[0].get("components") == sac_output.components

    def test_sac_failure_does_not_block_siblings(self):
        """If SAC fails, sibling features still run and SAC error is recorded."""
        mock_result = _make_mock_result(_make_sac_output())
        with (
            _patch_all_cve_feature_execs(mock_result),
            patch.object(
                cve_features.SuggestAffectedComponents,
                "exec",
                new_callable=AsyncMock,
                side_effect=RuntimeError("SAC timeout"),
            ),
        ):
            response = client.post(
                "/api/v1/analysis/cve",
                json={
                    "cve_id": "CVE-2024-1234",
                    "features": [
                        "suggest-affected-components",
                        "suggest-impact",
                    ],
                    "title": "kernel: buffer overflow",
                    "comment_zero": "A buffer overflow was found.",
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["results"]["suggest-affected-components"] is None
        assert "suggest-affected-components" in data["errors"]
        assert data["results"]["suggest-impact"] is not None
        assert "suggest-impact" not in data["errors"]

    def test_detail_flag(self):
        mock_result = _make_mock_result(_make_sac_output())

        with _patch_all_cve_feature_execs(mock_result):
            response = client.post(
                "/api/v1/analysis/cve?detail=true",
                json={
                    "cve_id": "CVE-2024-1234",
                    "features": ["suggest-affected-components"],
                },
            )
        assert response.status_code == 200
        data = response.json()
        result = data["results"]["suggest-affected-components"]
        assert result is not None


class TestResolveAgent:
    """Tests for per-request agent selection via _resolve_agent()."""

    def test_none_returns_default(self):
        assert _resolve_agent(None) is llm_agent

    def test_public_returns_public_agent(self):
        assert _resolve_agent("public") is public_feature_agent

    def test_redhat_returns_rh_agent(self):
        assert _resolve_agent("redhat") is rh_feature_agent

    def test_invalid_agent_raises_400(self):
        with pytest.raises(HTTPException) as exc_info:
            _resolve_agent("my_public_agent")
        assert exc_info.value.status_code == 400
        assert "Invalid agent" in exc_info.value.detail

    def test_case_sensitive_rejects_uppercase(self):
        with pytest.raises(HTTPException) as exc_info:
            _resolve_agent("PUBLIC")
        assert exc_info.value.status_code == 400


class TestAgentSelectionEndpoints:
    """Tests for per-request agent selection in POST CVE analysis endpoints."""

    def test_post_single_feature_with_public_agent(self):
        """POST /api/v1/analysis/cve/{feature} respects agent='public'."""
        mock_result = _make_mock_result(_make_sac_output())
        captured_agents = []

        def spy_init(self, agent):
            captured_agents.append(agent)
            Feature.__init__(self, agent)

        with (
            patch.object(
                cve_features.SuggestAffectedComponents,
                "__init__",
                spy_init,
            ),
            patch.object(
                cve_features.SuggestAffectedComponents,
                "exec",
                new_callable=AsyncMock,
                return_value=mock_result,
            ),
        ):
            response = client.post(
                "/api/v1/analysis/cve/suggest-affected-components",
                json={
                    "cve_id": "CVE-2024-1234",
                    "agent": "public",
                    "title": "Test title",
                    "cve_description": "Test description",
                },
            )
        assert response.status_code == 200
        assert len(captured_agents) == 1
        assert captured_agents[0] is public_feature_agent

    def test_post_multi_analysis_with_public_agent(self):
        """POST /api/v1/analysis/cve with agent='public' uses public agent."""
        mock_result = _make_mock_result(_make_sac_output())
        captured_agents = []

        def make_spy():
            def spy_init(self, agent):
                captured_agents.append(agent)
                Feature.__init__(self, agent)

            return spy_init

        from contextlib import ExitStack

        with ExitStack() as stack:
            for cls in cve_feature_registry.values():
                stack.enter_context(patch.object(cls, "__init__", make_spy()))
                stack.enter_context(
                    patch.object(
                        cls, "exec", new_callable=AsyncMock, return_value=mock_result
                    )
                )
            response = client.post(
                "/api/v1/analysis/cve",
                json={
                    "cve_id": "CVE-2024-1234",
                    "features": ["suggest-affected-components"],
                    "agent": "public",
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert "suggest-affected-components" in data["results"]
        assert data["errors"] == {}
        assert len(captured_agents) >= 1
        assert all(a is public_feature_agent for a in captured_agents)
