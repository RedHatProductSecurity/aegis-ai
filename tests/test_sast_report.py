"""Run the checked-in Tekton scripts locally with fake GitHub/OCI services.

Only the work volume and Tekton result path are substituted. Bash, jq, gzip,
base64 and GNU date parsing are real; the clock and external services are
controlled. The subprocess PATH contains only explicitly provisioned commands.
"""

import base64
import gzip
import json
import shutil
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

PIPELINE = Path(__file__).resolve().parents[1] / ".tekton/aegis-build-pipeline.yaml"
NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)
TOKEN = "test-only-token-must-not-appear-in-logs"
SECRET = "aegis-ai-code-scanning-alerts"
REAL_COMMANDS = (
    "bash",
    "jq",
    "date",
    "gzip",
    "base64",
    "sed",
    "mktemp",
    "rm",
    "cat",
    "cp",
    "mv",
    "mkdir",
    "basename",
    "rmdir",
    "wc",
)

# One small multicall executable replaces the two services, the presentation
# tool, and the clock. In particular, curl never falls through to a real client.
FAKE_COMMANDS = """\
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
case = json.loads(os.environ["SAST_CASE"])

def option(name):
    return args[args.index(name) + 1]

def curl():
    request = {
        "arguments": args,
        "payload": json.loads(Path(option("-d")[1:]).read_text()),
    }
    Path(os.environ["SAST_REQUEST"]).write_text(json.dumps(request))
    Path(option("-D")).write_bytes(case["headers"].encode())
    Path(option("-o")).write_text(json.dumps({"message": "fake GitHub response"}))
    sys.stdout.write(case["http_code"])
    if case["curl_exit"]:
        print("simulated curl transport failure", file=sys.stderr)
    return case["curl_exit"]

def oras():
    if args[0] == "discover":
        if case["discover_exit"]:
            print("simulated OCI discovery failure", file=sys.stderr)
            return case["discover_exit"]
        if "discover_output" in case:
            sys.stdout.write(case["discover_output"])
            return 0
        print(json.dumps({"referrers": [
            {"artifactType": "application/sarif+json", "reference": f"image@{i}"}
            for i in range(len(case["artifacts"]))
        ]}))
        return 0
    assert args[0] == "pull", args
    artifact = case["artifacts"][int(args[-1].split("@")[-1])]
    if artifact is None:
        print("simulated SARIF retrieval failure", file=sys.stderr)
        return 1
    (Path(option("-o")) / "scan.sarif").write_text(json.dumps(artifact))
    return 0

command = Path(sys.argv[0]).name
if command == "date":
    real_date = os.environ["SAST_REAL_DATE"]
    if "-d" not in args:
        args += ["-d", os.environ["SAST_NOW"]]
    os.execv(real_date, [real_date, *args])
elif command == "csgrep":
    print("formatted SAST findings")
else:
    sys.exit({"curl": curl, "oras": oras}[command]())
"""


def sarif(*levels: str | None) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "test-scanner"}},
                "results": [
                    {
                        "ruleId": f"rule-{index}",
                        "message": {"text": f"finding {index}: {level}"},
                        **({"level": level} if level is not None else {}),
                    }
                    for index, level in enumerate(levels)
                ],
            }
        ],
    }


@pytest.fixture(scope="module")
def sast_spec() -> dict[str, Any]:
    pipeline = yaml.safe_load(PIPELINE.read_text())
    return next(
        task["taskSpec"]
        for task in pipeline["spec"]["tasks"]
        if task["name"] == "sast-report"
    )


class SastScripts:
    def __init__(self, spec: dict[str, Any], root: Path, tools: dict[str, str]):
        self.spec = spec
        self.root = root
        self.tools = tools
        self.sarif_dir = root / "work dir" / "sarif"
        self.result_path = root / "TEST_OUTPUT"
        self.request_path = root / "request.json"
        self.logs = ""
        self.steps: dict[str, subprocess.CompletedProcess[str]] = {}
        self.case: dict[str, Any] = {
            "artifacts": [sarif()],
            "headers": "HTTP/2 202\r\n\r\n",
            "http_code": "202",
            "curl_exit": 0,
            "discover_exit": 0,
        }
        self.env = self._environment()

    def _environment(self) -> dict[str, str]:
        return {
            "PATH": str(self.root / "bin"),
            "HOME": str(self.root),
            "TMPDIR": str(self.root / "tmp"),
            "LC_ALL": "C",
            "TZ": "UTC",
            "SAST_REAL_DATE": self.tools["date"],
            "SAST_NOW": NOW.isoformat(),
            "SAST_REQUEST": str(self.request_path),
            "IMAGE_URL": "registry.example.test/image",
            "IMAGE_DIGEST": "sha256:" + "a" * 64,
            "GIT_URL": "https://github.com/example/project.git",
            "GIT_COMMIT_SHA": "abcdef0123" * 4,
            "GIT_REF": "main",
            "GITHUB_TOKEN": TOKEN,
        }

    def run_step(self, name: str) -> subprocess.CompletedProcess[str]:
        step = next(step for step in self.spec["steps"] if step["name"] == name)
        script = step["script"].replace("/var/workdir", str(self.sarif_dir.parent))
        script = script.replace("$(results.TEST_OUTPUT.path)", str(self.result_path))
        completed = subprocess.run(
            [self.tools["bash"]],
            input=script,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
            cwd=self.root,
            env={**self.env, "SAST_CASE": json.dumps(self.case)},
        )
        self.steps[name] = completed
        self.logs += completed.stdout + completed.stderr
        assert TOKEN not in self.logs
        return completed

    def run(self) -> subprocess.CompletedProcess[str]:
        # Honour the part of Tekton step sequencing relevant to onError.
        for step in self.spec["steps"]:
            completed = self.run_step(step["name"])
            if completed.returncode and step.get("onError") != "continue":
                return completed
        return completed

    def assert_result(self, expected: str, *, exit_code: int = 0) -> dict[str, Any]:
        assert self.result_path.is_file(), f"TEST_OUTPUT was not written:\n{self.logs}"
        raw = self.result_path.read_text()
        assert TOKEN not in raw
        status_path = self.sarif_dir / "upload_status.json"
        if status_path.exists():
            assert TOKEN not in status_path.read_text()
        result = json.loads(raw)
        assert result["result"] == expected, result
        assert list(self.steps.values())[-1].returncode == exit_code, self.logs
        assert isinstance(result["note"], str) and result["note"]
        assert result["namespace"] == "sast-report"
        assert result["version"] == "0.1"
        timestamp = datetime.fromisoformat(result["timestamp"])
        assert timestamp.utcoffset() == timedelta(0)
        for field in ("successes", "failures", "warnings"):
            assert type(result[field]) is int and result[field] >= 0, result
        return result

    def expiry_header(
        self, expiry: str, name: str = "GitHub-Authentication-Token-Expiration"
    ):
        self.case["headers"] = f"HTTP/2 202\r\n{name}: {expiry}\r\n\r\n"

    def fail_command(self, name: str):
        command = self.root / "bin" / name
        command.unlink()
        command.write_text(f"#!{self.tools['bash']}\nexit 73\n")
        command.chmod(0o755)


@pytest.fixture(scope="module")
def script_tools() -> dict[str, str]:
    tools = {}
    for name in REAL_COMMANDS:
        executable = shutil.which(name)
        if executable is None:
            pytest.skip(f"Tekton script tests require {name}")
        tools[name] = executable
    version = subprocess.run(
        [tools["date"], "--version"], capture_output=True, text=True, check=False
    )
    if "GNU coreutils" not in version.stdout:
        pytest.skip("Tekton script tests require GNU date")
    return tools


@pytest.fixture
def sast(sast_spec, script_tools, tmp_path: Path) -> SastScripts:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "tmp").mkdir()
    fake = bin_dir / "fake-command"
    fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent(FAKE_COMMANDS))
    fake.chmod(0o755)
    for name, executable in script_tools.items():
        (bin_dir / name).symlink_to(fake if name == "date" else executable)
    for name in ("curl", "oras", "csgrep"):
        (bin_dir / name).symlink_to(fake)
    return SastScripts(sast_spec, tmp_path, script_tools)


def test_tekton_wiring_keeps_upload_errors_nonblocking_and_report_gate_blocking(
    sast_spec,
):
    steps = {step["name"]: step for step in sast_spec["steps"]}
    names = list(steps)
    assert (
        names.index("pull-sarif") < names.index("upload-sarif") < names.index("report")
    )
    assert "TEST_OUTPUT" in {result["name"] for result in sast_spec["results"]}
    assert steps["pull-sarif"]["onError"] == "continue"
    assert steps["upload-sarif"]["onError"] == "continue"
    assert steps["report"].get("onError", "stopAndFail") == "stopAndFail"
    assert "$(results.TEST_OUTPUT.path)" in steps["report"]["script"]
    token = next(
        env for env in steps["upload-sarif"]["env"] if env["name"] == "GITHUB_TOKEN"
    )
    assert token["valueFrom"]["secretKeyRef"] == {
        "name": SECRET,
        "key": "token",
        "optional": True,
    }


@pytest.mark.parametrize(
    ("git_url", "ref", "expected_ref"),
    [
        ("https://github.com/example/project.git", "main", "refs/heads/main"),
        (
            "git@github.com:example/project.git",
            "refs/heads/release",
            "refs/heads/release",
        ),
        ("https://github.com/example/project", "refs/tags/v1.0", "refs/tags/v1.0"),
        (
            "https://github.com/example/project.git",
            "refs/pull/42/head",
            "refs/pull/42/head",
        ),
    ],
)
def test_healthy_upload_preserves_authentication_payload_and_refs(
    sast: SastScripts, git_url, ref, expected_ref
):
    artifacts = [sarif("note"), sarif("none"), sarif()]
    sast.case["artifacts"] = artifacts
    sast.env.update(GIT_URL=git_url, GIT_REF=ref)
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("SUCCESS")
    assert result["failures"] == result["warnings"] == 0
    request = json.loads(sast.request_path.read_text())
    arguments = request["arguments"]
    assert (
        "https://api.github.com/repos/example/project/code-scanning/sarifs" in arguments
    )
    assert arguments[arguments.index("-X") + 1] == "POST"
    assert f"Authorization: Bearer {TOKEN}" in arguments
    assert "Accept: application/vnd.github+json" in arguments
    assert "X-GitHub-Api-Version: 2022-11-28" in arguments
    assert "Content-Type: application/json" in arguments
    payload = request["payload"]
    assert payload["commit_sha"] == sast.env["GIT_COMMIT_SHA"]
    assert payload["ref"] == expected_ref
    merged = json.loads(
        gzip.decompress(base64.b64decode(payload["sarif"], validate=True))
    )
    assert merged["version"] == "2.1.0"
    assert len(merged["runs"]) == 1
    assert merged["runs"][0]["results"] == [
        finding for artifact in artifacts for finding in artifact["runs"][0]["results"]
    ]


@pytest.mark.parametrize(
    ("seconds_left", "expected"),
    [
        (14 * 86400 + 1, "SUCCESS"),
        (14 * 86400, "WARNING"),
        (14 * 86400 - 1, "WARNING"),
        (1, "WARNING"),
        (0, "WARNING"),
        (-1, "WARNING"),
        (-86400, "WARNING"),
    ],
)
def test_expiry_boundary_includes_exactly_fourteen_days_and_expired_tokens(
    sast: SastScripts, seconds_left, expected
):
    expiry = (NOW + timedelta(seconds=seconds_left)).strftime("%Y-%m-%d %H:%M:%S UTC")
    sast.expiry_header(expiry)
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result(expected)
    assert result["warnings"] == (1 if expected == "WARNING" else 0)
    assert expiry in sast.logs
    if expected == "WARNING":
        assert SECRET in result["note"]
        assert "rotate" in result["note"].lower()
        assert expiry in result["note"]
        if seconds_left <= 0:
            assert "expired" in result["note"].lower()


@pytest.mark.parametrize(
    ("header", "offset_hours", "seconds_left", "expected"),
    [
        ("github-authentication-token-expiration", 2, 14 * 86400, "WARNING"),
        ("gItHuB-AuThEnTiCaTiOn-ToKeN-ExPiRaTiOn", -5, 14 * 86400 + 1, "SUCCESS"),
    ],
)
def test_expiry_header_is_case_insensitive_and_parses_numeric_offsets_with_crlf(
    sast: SastScripts, header, offset_hours, seconds_left, expected
):
    expiry = (NOW + timedelta(seconds=seconds_left)).astimezone(
        timezone(timedelta(hours=offset_hours))
    )
    sast.expiry_header(expiry.strftime("%Y-%m-%d %H:%M:%S %z"), header)
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result(expected)


def test_missing_expiration_header_logs_unavailable_without_warning(sast: SastScripts):
    sast.case["headers"] = "HTTP/2 202\r\nContent-Type: application/json\r\n\r\n"
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("SUCCESS")
    assert result["warnings"] == 0
    assert "monitoring is unavailable" in sast.logs.lower()


@pytest.mark.parametrize(
    "expiry",
    [
        pytest.param("not-a-date", id="unparseable"),
        pytest.param("2026-02-30T12:00:00Z", id="invalid-calendar-date"),
        pytest.param("", id="empty-reported-date"),
    ],
)
def test_malformed_reported_expiry_warns_instead_of_looking_healthy(
    sast: SastScripts, expiry
):
    sast.expiry_header(expiry)
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    assert result["warnings"] >= 1
    assert "expir" in result["note"].lower()


@pytest.mark.parametrize(
    ("http_code", "curl_exit"),
    [
        ("401", 0),
        ("403", 0),
        ("422", 0),
        ("500", 0),
        ("000", 7),
        ("000", 28),
        ("202", 56),
    ],
)
def test_http_rejection_and_transport_failures_warn_and_allow_report(
    sast: SastScripts, http_code, curl_exit
):
    sast.case.update(http_code=http_code, curl_exit=curl_exit)
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    assert result["warnings"] >= 1
    assert result["failures"] == 0
    assert SECRET in result["note"]
    assert http_code in result["note"]


@pytest.mark.parametrize("token", [None, ""])
def test_missing_token_warns_without_attempting_upload(sast: SastScripts, token):
    if token is None:
        sast.env.pop("GITHUB_TOKEN")
    else:
        sast.env["GITHUB_TOKEN"] = token
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    assert SECRET in result["note"]
    assert "missing" in result["note"].lower()
    assert not sast.request_path.exists()


@pytest.mark.parametrize("missing", ["GIT_COMMIT_SHA", "GIT_REF", "GIT_URL"])
def test_unusable_upload_metadata_warns_without_attempting_upload(
    sast: SastScripts, missing
):
    sast.env[missing] = ""
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("WARNING")
    assert not sast.request_path.exists()


@pytest.mark.parametrize("gate_problem", [None, "error", "pull"])
def test_unexpected_preparation_failure_still_runs_report_and_preserves_gate(
    sast: SastScripts, gate_problem
):
    # Keep a SARIF file available even when another artifact cannot be pulled.
    artifacts: list[dict[str, Any] | None] = [sarif()]
    if gate_problem == "error":
        artifacts.append(sarif("error"))
    elif gate_problem == "pull":
        artifacts.append(None)
    sast.case["artifacts"] = artifacts
    # A local command failure before curl exercises set -e and Tekton onError.
    sast.fail_command("gzip")
    expected_exit = 1 if gate_problem else 0
    assert sast.run().returncode == expected_exit, sast.logs
    assert sast.steps["upload-sarif"].returncode != 0
    result = sast.assert_result(
        "FAILURE" if gate_problem else "WARNING", exit_code=expected_exit
    )
    assert result["warnings"] >= 1
    assert result["failures"] == expected_exit
    assert not sast.request_path.exists()


@pytest.mark.parametrize("gate_problem", ["error", "pull"])
@pytest.mark.parametrize("upload_problem", ["http", "expiry"])
def test_sast_errors_and_artifact_pull_failures_take_precedence_over_warnings(
    sast: SastScripts, gate_problem, upload_problem
):
    sast.case["artifacts"] = (
        [sarif("error", "warning")] if gate_problem == "error" else [None, sarif()]
    )
    if upload_problem == "http":
        sast.case["http_code"] = "403"
    else:
        sast.expiry_header((NOW + timedelta(days=1)).isoformat())
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] == 1
    assert result["successes"] == 0
    assert result["warnings"] >= 1
    assert SECRET in result["note"]
    assert ("error-level" if gate_problem == "error" else "retrieved") in result["note"]


def test_upload_and_expiry_warnings_are_both_visible(sast: SastScripts):
    sast.case["http_code"] = "403"
    sast.expiry_header((NOW + timedelta(days=2)).isoformat())
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    assert result["warnings"] == 2
    assert "403" in result["note"]
    assert "rotate" in result["note"].lower()


def test_warning_findings_remain_nonblocking_and_are_not_lost(sast: SastScripts):
    sast.case["artifacts"] = [sarif("warning", None, "note", "none")]
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    assert result["warnings"] == 2
    assert result["failures"] == 0
    assert "formatted SAST findings" in sast.logs


def test_no_sarif_artifacts_is_a_legitimate_skip_even_without_a_token(
    sast: SastScripts,
):
    sast.case["artifacts"] = []
    sast.env.pop("GITHUB_TOKEN")
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("SUCCESS")
    assert result["failures"] == result["warnings"] == 0
    assert "skip" in result["note"].lower()
    assert not sast.request_path.exists()


@pytest.mark.parametrize(
    "status",
    [
        pytest.param(None, id="missing"),
        pytest.param("", id="empty"),
        pytest.param("{", id="truncated-json"),
        pytest.param("null", id="null"),
        pytest.param("[]", id="array"),
        pytest.param('[{"warnings": 0, "note": "bad"}]', id="array-wrapped-status"),
        pytest.param('{"warnings": -1, "note": "bad"}', id="negative-count"),
        pytest.param('{"warnings": 0.5, "note": "bad"}', id="fractional-count"),
        pytest.param('{"warnings": "0", "note": "bad"}', id="string-count"),
        pytest.param('{"warnings": false, "note": "bad"}', id="boolean-count"),
        pytest.param('{"warnings": 0}', id="missing-note"),
        pytest.param('{"warnings": 0, "note": 42}', id="non-string-note"),
        pytest.param(
            '{"warnings": 0, "note": "first"}\n{"warnings": 0, "note": "second"}',
            id="multiple-json-documents",
        ),
        pytest.param(
            '{"warnings": 9223372036854775808, "note": "bad"}',
            id="count-overflows-shell-integer",
        ),
    ],
)
def test_missing_or_damaged_upload_status_cannot_produce_a_false_green_result(
    sast: SastScripts, status
):
    assert sast.run_step("pull-sarif").returncode == 0, sast.logs
    assert sast.run_step("upload-sarif").returncode == 0, sast.logs
    status_path = sast.sarif_dir / "upload_status.json"
    if status is None:
        status_path.unlink()
    else:
        status_path.write_text(status)
    assert sast.run_step("report").returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    assert result["warnings"] >= 1
    assert result["failures"] == 0


@pytest.mark.parametrize("encoded_count", ["1.0", "1e1", "2147483647"])
def test_positive_numeric_upload_status_cannot_crash_report_or_turn_green(
    sast: SastScripts, encoded_count
):
    assert sast.run_step("pull-sarif").returncode == 0, sast.logs
    # JSON numbers with decimal/exponent spelling can still have integer values.
    (sast.sarif_dir / "upload_status.json").write_text(
        f'{{"warnings": {encoded_count}, "note": "upload warning"}}'
    )
    assert sast.run_step("report").returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    # Either consume the count safely or fall back to an unavailable-status
    # warning; a spelling the shell cannot consume must not become a hard gate.
    assert result["warnings"] >= 1


def test_artifact_discovery_failure_has_a_failure_result_and_nonzero_exit(
    sast: SastScripts,
):
    sast.case["discover_exit"] = 1
    assert sast.run().returncode != 0, sast.logs
    sast.assert_result("FAILURE", exit_code=1)


@pytest.mark.parametrize(
    "output",
    [pytest.param("", id="empty-response"), pytest.param("{", id="invalid-json")],
)
def test_invalid_discovery_response_cannot_be_mistaken_for_no_artifacts(
    sast: SastScripts, output
):
    sast.case["discover_output"] = output
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] >= 1
    assert result["successes"] == 0


@pytest.mark.parametrize("missing", ["IMAGE_URL", "IMAGE_DIGEST"])
def test_missing_image_metadata_still_emits_a_gate_failure(sast: SastScripts, missing):
    sast.env[missing] = ""
    assert sast.run().returncode == 1, sast.logs
    assert sast.steps["pull-sarif"].returncode != 0
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] >= 1
    assert not sast.request_path.exists()


def test_unexpected_error_after_artifact_pull_preserves_failure_fallback(
    sast: SastScripts,
):
    sast.fail_command("mv")
    assert sast.run().returncode == 1, sast.logs
    assert sast.steps["pull-sarif"].returncode != 0
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] >= 1
