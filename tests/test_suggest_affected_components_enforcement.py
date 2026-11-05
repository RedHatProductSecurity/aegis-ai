"""Offline tests of the AEGIS-496 Go module identity enforcement.

Covers the eval-suite exact-matching scope, the advisory-parsing helpers,
and the SuggestAffectedComponents._check_output output-enforcement guards.
"""

from pathlib import Path

import pytest
from pydantic_ai import Agent
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.test import TestModel

from aegis_ai import get_settings
from aegis_ai.agents import rh_feature_agent
from aegis_ai.features.cve import (
    _GHSA_TOOL_NAME,
    SuggestAffectedComponents,
    _advisory_go_module_paths,
    _agent_tool_names,
    _module_root,
)
from aegis_ai.features.cve.data_models import SuggestAffectedComponentsModel
from aegis_ai.features.data_models import feature_deps
from evals.features.cve import test_suggest_affected_components as component_evals

CACHE_DIR = Path(__file__).parents[1] / "evals/osidb_cache"

PODMAN_V4 = "github.com/containers/podman/v4"
PODMAN_V5 = "github.com/containers/podman/v5"

GHSA_ID = "GHSA-4rj7-6vg4-5xh7"
GHSA_URL = f"https://github.com/advisories/{GHSA_ID}"

NON_GHSA_URL = "https://nvd.nist.gov/vuln/detail/CVE-2026-37236"


class TestEvalExactMatchingScope:
    """Only the two AEGIS-496 CVEs are exact-matched by the eval suite."""

    def test_go_module_identity_cve_ids_limited_to_aegis_496_pair(self):
        assert component_evals.GO_MODULE_IDENTITY_CVE_IDS == (
            "CVE-2026-37236",
            "CVE-2026-81521",
        )

    def test_exact_components_metadata_only_for_aegis_496_cves(self, monkeypatch):
        monkeypatch.setattr(component_evals, "OSIDB_CACHE_DIR", CACHE_DIR)
        former_members = {"CVE-2025-64329", "CVE-2026-33414"}
        aegis_496 = set(component_evals.GO_MODULE_IDENTITY_CVE_IDS)

        cases = {
            case.inputs: case
            for case in component_evals._build_cases(
                cve_id_filter=former_members | aegis_496
            )
        }

        assert set(cases) == former_members | aegis_496
        for cve_id in aegis_496:
            metadata = cases[cve_id].metadata
            assert metadata is not None
            assert metadata["require_exact_components"] is True
            assert any(
                isinstance(e, component_evals.ExactComponentsEvaluator)
                for e in cases[cve_id].evaluators
            )
        for cve_id in former_members:
            metadata = cases[cve_id].metadata
            assert metadata is not None
            assert "require_exact_components" not in metadata
            assert not any(
                isinstance(e, component_evals.ExactComponentsEvaluator)
                for e in cases[cve_id].evaluators
            )


@pytest.mark.parametrize(
    ("module_path", "root"),
    [
        ("github.com/go-acme/lego/v4", "github.com/go-acme/lego"),
        ("golang.org/x/net/html", "golang.org/x/net/html"),
        ("go.mongodb.org/mongo-driver/v2", "go.mongodb.org/mongo-driver"),
        (
            "github.com/grpc-ecosystem/grpc-gateway/v2",
            "github.com/grpc-ecosystem/grpc-gateway",
        ),
        (
            "github.com/grpc-ecosystem/grpc-gateway",
            "github.com/grpc-ecosystem/grpc-gateway",
        ),
    ],
)
def test_module_root_strips_only_trailing_major_suffix(module_path, root):
    assert _module_root(module_path) == root


def _affected(name: str, ecosystem: str) -> dict:
    return {"package": {"name": name, "ecosystem": ecosystem}}


def _osv_advisory(*affected: dict) -> dict:
    return {
        "id": GHSA_ID,
        "summary": "Offline advisory fixture",
        "details": "",
        "affected": list(affected),
        "database_specific": {},
    }


def _tool_return(tool_name: str, content) -> ModelRequest:
    return ModelRequest(parts=[ToolReturnPart(tool_name=tool_name, content=content)])


def _ghsa_tool_call() -> ModelResponse:
    return ModelResponse(
        parts=[ToolCallPart(tool_name=_GHSA_TOOL_NAME, args={"references": [GHSA_URL]})]
    )


class TestAdvisoryGoModulePaths:
    """_advisory_go_module_paths maps OSV tool returns to Go module paths."""

    def test_groups_major_versions_by_repository_root(self):
        messages = [
            _tool_return(
                _GHSA_TOOL_NAME,
                [_osv_advisory(_affected(PODMAN_V4, "Go"), _affected(PODMAN_V5, "Go"))],
            )
        ]

        assert _advisory_go_module_paths(messages) == {
            "github.com/containers/podman": {PODMAN_V4, PODMAN_V5}
        }

    def test_ecosystem_match_is_case_insensitive(self):
        messages = [
            _tool_return(
                _GHSA_TOOL_NAME,
                [_osv_advisory(_affected(PODMAN_V4, "Go"), _affected(PODMAN_V5, "go"))],
            )
        ]

        assert _advisory_go_module_paths(messages) == {
            "github.com/containers/podman": {PODMAN_V4, PODMAN_V5}
        }

    def test_ignores_non_go_ecosystems(self):
        messages = [
            _tool_return(
                _GHSA_TOOL_NAME,
                [_osv_advisory(_affected("tar", "npm"), _affected("tar", "PyPI"))],
            )
        ]

        assert _advisory_go_module_paths(messages) == {}

    def test_handles_single_dict_content(self):
        messages = [
            _tool_return(
                "osv_dev_cve_tool",
                _osv_advisory(_affected(PODMAN_V4, "Go"), _affected(PODMAN_V5, "Go")),
            )
        ]

        assert _advisory_go_module_paths(messages) == {
            "github.com/containers/podman": {PODMAN_V4, PODMAN_V5}
        }

    def test_ignores_unrelated_tools_and_non_tool_return_parts(self):
        messages = [
            ModelRequest(parts=[UserPromptPart(content="analyze the CVE")]),
            _tool_return(
                "osidb_tool",
                [_osv_advisory(_affected(PODMAN_V4, "Go"), _affected(PODMAN_V5, "Go"))],
            ),
            _ghsa_tool_call(),
        ]

        assert _advisory_go_module_paths(messages) == {}


class _FakeResult:
    """Minimal AgentRunResult stand-in exposing output and message history."""

    def __init__(self, components: list[str], messages: list):
        schema = SuggestAffectedComponentsModel.model_json_schema()
        self.output = SuggestAffectedComponentsModel(
            cve_id="CVE-2026-37236",
            components=components,
            explanation="Offline enforcement input, not an inferred model response.",
            confidence=1.0,
            data_quality=1.0,
            disclaimer=schema["properties"]["disclaimer"]["const"],
        )
        self._messages = messages

    def all_messages(self):
        return self._messages


@pytest.fixture
def rh_components_feature(monkeypatch):
    """SuggestAffectedComponents on the RH agent, OSV.dev gating enabled."""
    monkeypatch.setattr(get_settings(), "use_osv_dev_tool", True)
    return SuggestAffectedComponents(rh_feature_agent)


class TestCheckOutputAvailabilityGating:
    """_check_output only enforces when the GHSA tool is actually usable."""

    def test_rh_feature_agent_toolset_graph_exposes_ghsa_tool(self):
        names: set[str] = set()
        for toolset in rh_feature_agent.toolsets:
            names |= _agent_tool_names(toolset)

        assert _GHSA_TOOL_NAME in names

    def test_silent_for_toolless_agent(self, monkeypatch):
        monkeypatch.setattr(get_settings(), "use_osv_dev_tool", True)
        agent = Agent(TestModel(), output_type=SuggestAffectedComponentsModel)
        feature = SuggestAffectedComponents(agent)  # ty: ignore[invalid-argument-type]
        deps = feature_deps(cve_id="CVE-2026-37236", allowed_reference_urls={GHSA_URL})

        assert feature._check_output(_FakeResult(["grpc-gateway"], []), deps) is None

    def test_silent_when_ghsa_tool_disabled_for_run(self, monkeypatch):
        monkeypatch.setattr(get_settings(), "use_osv_dev_tool", True)
        feature = SuggestAffectedComponents(rh_feature_agent)
        deps = feature_deps(
            cve_id="CVE-2026-37236",
            allowed_reference_urls={GHSA_URL},
            disabled_tools={_GHSA_TOOL_NAME},
        )

        assert feature._check_output(_FakeResult(["grpc-gateway"], []), deps) is None

    def test_silent_when_osv_dev_tools_disabled_in_settings(self, monkeypatch):
        monkeypatch.setattr(get_settings(), "use_osv_dev_tool", False)
        feature = SuggestAffectedComponents(rh_feature_agent)
        deps = feature_deps(cve_id="CVE-2026-37236", allowed_reference_urls={GHSA_URL})

        assert feature._check_output(_FakeResult(["grpc-gateway"], []), deps) is None


class TestCheckOutputModulePathGuard:
    """Guard 2: advisory-listed Go module paths must survive into components."""

    def test_requests_retry_when_advisory_module_path_missing(
        self, rh_components_feature
    ):
        messages = [
            _tool_return(
                _GHSA_TOOL_NAME,
                [_osv_advisory(_affected(PODMAN_V4, "Go"), _affected(PODMAN_V5, "Go"))],
            ),
            _ghsa_tool_call(),
        ]
        deps = feature_deps(cve_id="CVE-2026-33414", allowed_reference_urls={GHSA_URL})

        retry = rh_components_feature._check_output(
            _FakeResult([PODMAN_V4], messages), deps
        )

        assert retry is not None
        assert PODMAN_V5 in retry
        assert PODMAN_V4 not in retry
        assert "components" in retry

    def test_accepts_when_all_advisory_paths_present(self, rh_components_feature):
        messages = [
            _tool_return(
                _GHSA_TOOL_NAME,
                [_osv_advisory(_affected(PODMAN_V4, "Go"), _affected(PODMAN_V5, "Go"))],
            ),
            _ghsa_tool_call(),
        ]
        deps = feature_deps(cve_id="CVE-2026-33414", allowed_reference_urls={GHSA_URL})

        retry = rh_components_feature._check_output(
            _FakeResult([PODMAN_V4, PODMAN_V5, "podman"], messages), deps
        )

        assert retry is None

    def test_single_module_path_root_stays_model_discretionary(
        self, rh_components_feature
    ):
        messages = [
            _tool_return(
                _GHSA_TOOL_NAME,
                [
                    _osv_advisory(
                        _affected("github.com/oauth2-proxy/oauth2-proxy/v7", "Go")
                    )
                ],
            ),
            _ghsa_tool_call(),
        ]
        deps = feature_deps(cve_id="CVE-2026-40575", allowed_reference_urls={GHSA_URL})

        retry = rh_components_feature._check_output(
            _FakeResult(
                ["oauth2-proxy", "github.com/oauth2-proxy/oauth2-proxy"], messages
            ),
            deps,
        )

        assert retry is None


class TestCheckOutputToolCallGuard:
    """Guard 1: GHSA references present means the GHSA tool must be called."""

    def test_requests_retry_when_ghsa_tool_never_called(self, rh_components_feature):
        deps = feature_deps(cve_id="CVE-2026-37236", allowed_reference_urls={GHSA_URL})

        retry = rh_components_feature._check_output(
            _FakeResult(["github.com/grpc-ecosystem/grpc-gateway"], []), deps
        )

        assert retry is not None
        assert GHSA_ID in retry
        assert _GHSA_TOOL_NAME in retry

    def test_accepts_when_ghsa_tool_call_in_history(self, rh_components_feature):
        messages = [
            _ghsa_tool_call(),
            _tool_return(
                _GHSA_TOOL_NAME,
                [
                    _osv_advisory(
                        _affected("github.com/grpc-ecosystem/grpc-gateway", "Go"),
                        _affected("github.com/grpc-ecosystem/grpc-gateway/v2", "Go"),
                    )
                ],
            ),
        ]
        deps = feature_deps(cve_id="CVE-2026-37236", allowed_reference_urls={GHSA_URL})

        retry = rh_components_feature._check_output(
            _FakeResult(
                [
                    "github.com/grpc-ecosystem/grpc-gateway",
                    "github.com/grpc-ecosystem/grpc-gateway/v2",
                ],
                messages,
            ),
            deps,
        )

        assert retry is None

    def test_accepts_when_references_contain_no_ghsa_id(self, rh_components_feature):
        deps = feature_deps(
            cve_id="CVE-2026-23950", allowed_reference_urls={NON_GHSA_URL}
        )

        retry = rh_components_feature._check_output(_FakeResult(["tar"], []), deps)

        assert retry is None

    @pytest.mark.parametrize(
        "reference",
        [
            {"url": GHSA_URL},
            GHSA_URL,
        ],
        ids=["dict-form", "string-form"],
    )
    def test_static_context_references_scanned_for_ghsa_ids(
        self, rh_components_feature, reference
    ):
        deps = feature_deps(
            cve_id="CVE-2026-37236",
            static_context={"references": [reference]},
        )

        retry = rh_components_feature._check_output(_FakeResult(["tar"], []), deps)

        assert retry is not None
        assert GHSA_ID in retry
        assert _GHSA_TOOL_NAME in retry
