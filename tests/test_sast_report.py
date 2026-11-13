"""Run the checked-in Tekton scripts locally with fake GitHub/OCI services.

Only the work volume and Tekton result path are substituted. Bash, jq, gzip,
base64 and GNU date parsing are real; the clock and external services are
controlled. The subprocess PATH contains only explicitly provisioned commands.
"""

import base64
import copy
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
SAST_TASK = PIPELINE.with_name("sast-report.yaml")
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
    "find",
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
    out = Path(option("-o"))
    # An artifact of the form {"layout": {relpath: content}} writes files at
    # arbitrary relative paths; a str content is written verbatim (raw bytes,
    # e.g. unparseable text), anything else is written as JSON.
    if "layout" in artifact:
        for rel, content in artifact["layout"].items():
            target = out / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                target.write_text(content)
            else:
                target.write_text(json.dumps(content))
        return 0
    (out / "scan.sarif").write_text(json.dumps(artifact))
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
    """Build a single-run SARIF document with one result per given level."""
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


def sarif_with_rules(
    rules: list[dict[str, Any]],
    results: list[dict[str, Any]],
    *,
    tool: str = "test-scanner",
    bases: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a single-run SARIF document with explicit rules, results, and URI bases."""
    run: dict[str, Any] = {
        "tool": {"driver": {"name": tool, "rules": rules}},
        "results": results,
    }
    if bases is not None:
        run["originalUriBaseIds"] = bases
    return {"version": "2.1.0", "runs": [run]}


@pytest.fixture(scope="module")
def sast_spec() -> dict[str, Any]:
    """Load the extracted sast-report task spec once per module."""
    return yaml.safe_load(SAST_TASK.read_text())["spec"]


class SastScripts:
    """Run the sast-report task steps locally against the fake services."""

    def __init__(self, spec: dict[str, Any], root: Path, tools: dict[str, str]):
        """Set up sandbox paths, a default healthy case, and the step environment."""
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
        """Build the sandboxed environment with a fixed clock and upload metadata."""
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
        """Run one task step by name with its paths rewired into the sandbox."""
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
        """Run every step in order, honouring onError, and return the last process."""
        # Honour the part of Tekton step sequencing relevant to onError.
        for step in self.spec["steps"]:
            completed = self.run_step(step["name"])
            if completed.returncode and step.get("onError") != "continue":
                return completed
        return completed

    def assert_result(self, expected: str, *, exit_code: int = 0) -> dict[str, Any]:
        """Assert the report wrote a well-formed TEST_OUTPUT with the expected result."""
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
        """Serve the token-expiration header with the given date on the next upload."""
        self.case["headers"] = f"HTTP/2 202\r\n{name}: {expiry}\r\n\r\n"

    def uploaded_sarif(self) -> dict[str, Any]:
        """Return the SARIF document that was POSTed to GitHub."""
        request = json.loads(self.request_path.read_text())
        return json.loads(
            gzip.decompress(
                base64.b64decode(request["payload"]["sarif"], validate=True)
            )
        )

    def fail_command(self, name: str, *, on_call: int = 1):
        """Wrap a sandbox command so it fails on its Nth invocation."""
        command = self.root / "bin" / name
        command.unlink()
        command.write_text(
            f"#!{self.tools['bash']}\n"
            "count=0\n"
            f'[[ ! -f "{command}.calls" ]] || read -r count < "{command}.calls"\n'
            f'echo "$((count + 1))" > "{command}.calls"\n'
            f"[[ $((count + 1)) -ne {on_call} ]] || exit 73\n"
            f'exec "{self.tools[name]}" "$@"\n'
        )
        command.chmod(0o755)


@pytest.fixture(scope="module")
def script_tools() -> dict[str, str]:
    """Resolve the real GNU tools the scripts need, skipping the module when absent."""
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
    """Build the per-test sandbox of real tools and fake curl, oras, csgrep, and date."""
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


@pytest.mark.parametrize(
    ("event", "source_revision", "pipeline_revision"),
    [
        ("pull-request", "a" * 40, "a" * 40),
        ("push", "b" * 40, "main"),
        ("push", "refs/tags/v1.2.3", "main"),
    ],
)
def test_pipeline_and_extracted_task_keep_original_revision_selection(
    event, source_revision, pipeline_revision
):
    """Runs resolve the pipeline from the event revision and the task from pipeline-revision."""
    run = yaml.safe_load(PIPELINE.with_name(f"aegis-ai-{event}.yaml").read_text())
    reference = run["spec"]["pipelineRef"]
    assert reference["resolver"] == "git"
    assert {param["name"]: param["value"] for param in reference["params"]} == {
        "url": "$(params.git-url)",
        "revision": "$(params.revision)" if event == "pull-request" else "main",
        "pathInRepo": ".tekton/aegis-build-pipeline.yaml",
        "kind": "pipeline",
    }
    pipeline = yaml.safe_load(PIPELINE.read_text())["spec"]
    parameters = {
        param["name"]: param["default"]
        for param in pipeline["params"]
        if "default" in param
    }
    parameters.update(
        (param["name"], param["value"].replace("{{revision}}", source_revision))
        for param in run["spec"]["params"]
        if param["name"] in {"revision", "pipeline-revision"}
    )
    assert parameters["revision"] == source_revision
    assert parameters["pipeline-revision"] == pipeline_revision
    task = next(task for task in pipeline["tasks"] if task["name"] == "sast-report")
    assert task["taskRef"]["resolver"] == "git"
    assert {param["name"]: param["value"] for param in task["taskRef"]["params"]} == {
        "url": "$(params.git-url)",
        "revision": "$(params.pipeline-revision)",
        "pathInRepo": ".tekton/sast-report.yaml",
        "kind": "task",
    }


def test_extracted_task_preserves_source_revision_binding_and_sast_gate(sast_spec):
    """The extracted task keeps the pipeline parameter bindings, gate, and ordering."""
    pipeline = yaml.safe_load(PIPELINE.read_text())
    tasks = {task["name"]: task for task in pipeline["spec"]["tasks"]}
    sast = tasks["sast-report"]
    assert "taskSpec" not in sast
    extracted = yaml.safe_load(SAST_TASK.read_text())
    assert extracted["kind"] == "Task"
    assert extracted["metadata"]["name"] == "sast-report"
    bindings = {param["name"]: param["value"] for param in sast["params"]}
    assert {param["name"] for param in sast_spec["params"]} == bindings.keys()
    assert bindings["revision"] == "$(params.revision)"
    upload = next(step for step in sast_spec["steps"] if step["name"] == "upload-sarif")
    assert next(env for env in upload["env"] if env["name"] == "GIT_COMMIT_SHA") == {
        "name": "GIT_COMMIT_SHA",
        "value": "$(params.revision)",
    }
    assert set(sast["runAfter"]) == {
        "sast-snyk-check",
        "sast-shell-check",
        "sast-unicode-check",
    }
    assert set(sast["runAfter"]) <= tasks.keys()
    assert sast["when"] == [
        {"input": "$(params.skip-checks)", "operator": "in", "values": ["false"]}
    ]


def test_tekton_wiring_keeps_upload_errors_nonblocking_and_report_gate_blocking(
    sast_spec,
):
    """Upload steps continue on error while the report step blocks and writes TEST_OUTPUT."""
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
    """A healthy upload POSTs correct headers, ref, and merged SARIF to the API."""
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
    """Expiry warnings start at exactly fourteen days remaining and cover expired tokens."""
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
    """The expiry header matches case-insensitively and numeric offsets parse."""
    expiry = (NOW + timedelta(seconds=seconds_left)).astimezone(
        timezone(timedelta(hours=offset_hours))
    )
    sast.expiry_header(expiry.strftime("%Y-%m-%d %H:%M:%S %z"), header)
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result(expected)


def test_missing_expiration_header_logs_unavailable_without_warning(sast: SastScripts):
    """A missing expiry header logs unavailability without producing a warning."""
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
    """An unparseable expiry date warns rather than reporting a healthy upload."""
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
    """HTTP rejections and curl failures warn without failing the pipeline."""
    sast.case.update(http_code=http_code, curl_exit=curl_exit)
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    assert result["warnings"] >= 1
    assert result["failures"] == 0
    assert SECRET in result["note"]
    assert http_code in result["note"]


@pytest.mark.parametrize("token", [None, ""])
def test_missing_token_warns_without_attempting_upload(sast: SastScripts, token):
    """A missing or empty token warns without sending any upload request."""
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
    """Empty git metadata warns without sending any upload request."""
    sast.env[missing] = ""
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("WARNING")
    assert not sast.request_path.exists()


@pytest.mark.parametrize("gate_problem", [None, "error"])
def test_unexpected_preparation_failure_still_runs_report_and_preserves_gate(
    sast: SastScripts, gate_problem
):
    """A local command failure still runs the report and keeps the SAST gate intact."""
    artifacts = [sarif()]
    if gate_problem == "error":
        artifacts.append(sarif("error"))
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


@pytest.mark.parametrize("upload_problem", ["http", "expiry"])
def test_sast_errors_take_precedence_over_upload_warnings(
    sast: SastScripts, upload_problem
):
    """Error-level findings fail the pipeline even when upload warnings are present."""
    sast.case["artifacts"] = [sarif("error", "warning")]
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
    assert "error-level" in result["note"]
    assert sast.request_path.exists()


@pytest.mark.parametrize("failed_first", [False, True])
def test_partial_artifact_retrieval_never_merges_or_uploads(
    sast: SastScripts, failed_first
):
    """A failed artifact pull prevents any merge or upload of the collected results."""
    sast.case["artifacts"] = (
        [None, sarif("note")] if failed_first else [sarif("note"), None]
    )
    assert sast.run().returncode == 1, sast.logs
    assert list(sast.sarif_dir.glob("*_scan.sarif"))
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["successes"] == 0
    assert result["failures"] > 0
    assert result["warnings"] > 0
    assert "skipped" in result["note"]
    assert not sast.request_path.exists()
    assert not (sast.sarif_dir / "merged.sarif.json").exists()


def test_collection_failure_after_first_artifact_never_uploads_partial_results(
    sast: SastScripts,
):
    """A mid-collection move failure counts as a pull failure and uploads nothing."""
    # A move failure mid-collection is a handled pull failure: the step
    # still completes so the report can run, but retrieval stays incomplete
    # and nothing partially collected is ever uploaded or merged.
    sast.case["artifacts"] = [sarif("note"), sarif("error")]
    sast.fail_command("mv", on_call=2)
    assert sast.run().returncode == 1, sast.logs
    assert sast.steps["pull-sarif"].returncode == 0, sast.logs
    assert (sast.sarif_dir / "1_scan.sarif").exists()
    assert not (sast.sarif_dir / "2_scan.sarif").exists()
    assert (sast.sarif_dir / "ref_2").is_dir()
    summary = dict(
        line.split("=", 1)
        for line in (sast.sarif_dir / "summary.env").read_text().splitlines()
    )
    assert summary["PULL_FAILURES"] == "1"
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["successes"] == 0
    assert result["failures"] > 0
    assert result["warnings"] > 0
    assert "skipped" in result["note"]
    assert not sast.request_path.exists()
    assert not (sast.sarif_dir / "merged.sarif.json").exists()


@pytest.mark.parametrize("gate_written", [False, True])
def test_interrupted_final_bookkeeping_cannot_upload(sast: SastScripts, gate_written):
    """A pull-step crash around its gate bookkeeping cannot upload partial results."""
    # Simulate the pull process dying after writing its zero-count summary,
    # on either side of committing its gate status. All artifact files exist.
    sast.spec = copy.deepcopy(sast.spec)
    pull = next(step for step in sast.spec["steps"] if step["name"] == "pull-sarif")
    boundary = (
        'echo "$GATE_EXIT" > "$SARIF_DIR/gate_exit"' if gate_written else "GATE_EXIT=0"
    )
    assert boundary in pull["script"]
    interruption = f"{boundary}\nexit 73" if gate_written else f"exit 73\n{boundary}"
    pull["script"] = pull["script"].replace(boundary, interruption, 1)
    expected_exit = 0 if gate_written else 1
    assert sast.run().returncode == expected_exit, sast.logs
    assert sast.steps["pull-sarif"].returncode == 73
    assert (sast.sarif_dir / "1_scan.sarif").exists()
    summary = (sast.sarif_dir / "summary.env").read_text().splitlines()
    assert summary and all(line.endswith("=0") for line in summary)
    result = sast.assert_result(
        "WARNING" if gate_written else "FAILURE", exit_code=expected_exit
    )
    assert result["warnings"] > 0
    if not gate_written:
        assert result["successes"] == 0
        assert result["failures"] > 0
    assert not sast.request_path.exists()
    assert not (sast.sarif_dir / "merged.sarif.json").exists()


@pytest.mark.parametrize("upload_warnings", [0, 2])
def test_nonzero_gate_overrides_zero_summary_counts(sast: SastScripts, upload_warnings):
    """A nonzero gate exit fails the report even when the summary counts are zero."""
    sast.sarif_dir.mkdir(parents=True)
    (sast.sarif_dir / "summary.env").write_text(
        "TOTAL_ERRORS=0\nTOTAL_WARNINGS=0\nTOTAL_NOTES=0\nPULL_FAILURES=0\n"
    )
    (sast.sarif_dir / "gate_exit").write_text("1\n")
    (sast.sarif_dir / "upload_status.json").write_text(
        json.dumps({"warnings": upload_warnings, "note": "test upload status"})
    )
    assert sast.run_step("report").returncode != 0, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["successes"] == 0
    assert result["failures"] > 0
    assert result["warnings"] == upload_warnings


def test_fully_retrieved_error_findings_still_upload(sast: SastScripts):
    """Error findings still upload when artifact retrieval completed."""
    artifact = sarif("error", "warning")
    sast.case["artifacts"] = [artifact]
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["successes"] == 0
    assert result["failures"] == 1
    request = json.loads(sast.request_path.read_text())
    assert "POST" in request["arguments"]
    uploaded = json.loads(
        gzip.decompress(base64.b64decode(request["payload"]["sarif"]))
    )
    assert uploaded == artifact


def test_upload_and_expiry_warnings_are_both_visible(sast: SastScripts):
    """Upload failures and near-expiry tokens both surface as visible warnings."""
    sast.case["http_code"] = "403"
    sast.expiry_header((NOW + timedelta(days=2)).isoformat())
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    assert result["warnings"] == 2
    assert "403" in result["note"]
    assert "rotate" in result["note"].lower()


def test_warning_findings_remain_nonblocking_and_are_not_lost(sast: SastScripts):
    """Warning-level findings stay non-blocking yet remain visible in the result."""
    sast.case["artifacts"] = [sarif("warning", None, "note", "none")]
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("WARNING")
    assert result["warnings"] == 2
    assert result["failures"] == 0
    assert "formatted SAST findings" in sast.logs


def test_nested_and_hidden_sarif_files_are_collected_counted_and_merged(
    sast: SastScripts,
):
    """Nested and hidden SARIF files are collected, counted, and merged into one upload."""
    sast.case["artifacts"] = [
        {
            "layout": {
                "reports/tool-a.sarif": sarif("note"),
                "deep/dir/tool-b.sarif": sarif("warning"),
                ".hidden.sarif": sarif(None),
            }
        }
    ]
    assert sast.run().returncode == 0, sast.logs
    names = sorted(path.name for path in sast.sarif_dir.glob("1_*"))
    assert names == [
        "1_.hidden.sarif",
        "1_deep_sdir_stool-b.sarif",
        "1_reports_stool-a.sarif",
    ]
    result = sast.assert_result("WARNING")
    assert result["warnings"] == 2
    assert result["failures"] == 0
    merged = sast.uploaded_sarif()
    assert len(merged["runs"]) == 1
    assert len(merged["runs"][0]["results"]) == 3


def test_collection_flattening_keeps_underscore_and_separator_names_distinct(
    sast: SastScripts,
):
    """Flattening escapes keep a_b.sarif and a/b.sarif collection names distinct."""
    sast.case["artifacts"] = [
        {"layout": {"a_b.sarif": sarif("note"), "a/b.sarif": sarif("warning")}}
    ]
    assert sast.run().returncode == 0, sast.logs
    assert (sast.sarif_dir / "1_a__b.sarif").exists()
    assert (sast.sarif_dir / "1_a_sb.sarif").exists()
    result = sast.assert_result("WARNING")
    assert result["warnings"] == 1
    assert result["failures"] == 0


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("not json at all", id="invalid-json"),
        pytest.param('{"version": "2.1.0"}', id="missing-runs"),
        pytest.param('{"runs": "hello"}', id="runs-not-an-array"),
        pytest.param('{"runs": [1, 2]}', id="runs-not-objects"),
        pytest.param(
            json.dumps(sarif("note")) + json.dumps(sarif("error")),
            id="two-concatenated-documents",
        ),
        pytest.param(
            json.dumps(sarif("note")) + "trailing garbage",
            id="trailing-garbage",
        ),
    ],
)
def test_unparseable_sarif_counts_as_retrieval_failure(sast: SastScripts, content):
    """Malformed SARIF counts as a retrieval failure instead of being silently skipped."""
    sast.case["artifacts"] = [{"layout": {"scan.sarif": content}}]
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["successes"] == 0
    assert result["failures"] >= 1
    assert "could not be retrieved" in result["note"]
    summary = dict(
        line.split("=", 1)
        for line in (sast.sarif_dir / "summary.env").read_text().splitlines()
    )
    assert summary["PULL_FAILURES"] == "1"
    assert summary["TOTAL_ERRORS"] == "0"
    assert not sast.request_path.exists()
    assert not (sast.sarif_dir / "merged.sarif.json").exists()


@pytest.mark.parametrize("reference", ["rule-index", "rule-id"])
def test_rule_default_error_level_fails_the_gate(sast: SastScripts, reference):
    """A rule's default error level fails the gate via ruleIndex or ruleId lookup."""
    results: list[dict[str, Any]] = [{"ruleId": "rule-0"}]
    if reference == "rule-index":
        results[0]["ruleIndex"] = 0
    sast.case["artifacts"] = [
        sarif_with_rules(
            [{"id": "rule-0", "defaultConfiguration": {"level": "error"}}], results
        )
    ]
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] == 1
    assert result["warnings"] == 0
    assert "error-level" in result["note"]


def test_out_of_bounds_rule_index_falls_back_to_rule_id_lookup(sast: SastScripts):
    """An out-of-range ruleIndex falls back to resolving the level by ruleId."""
    sast.case["artifacts"] = [
        sarif_with_rules(
            [{"id": "rule-0", "defaultConfiguration": {"level": "error"}}],
            [{"ruleId": "rule-0", "ruleIndex": 7}],
        )
    ]
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] == 1


def test_rule_default_note_level_stays_nonblocking(sast: SastScripts):
    """A rule's default note level stays non-blocking."""
    sast.case["artifacts"] = [
        sarif_with_rules(
            [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
            [{"ruleId": "rule-0"}],
        )
    ]
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("SUCCESS")
    assert result["failures"] == result["warnings"] == 0


def test_result_kind_other_than_fail_counts_as_none(sast: SastScripts):
    """A result whose kind is not "fail" counts as level none."""
    sast.case["artifacts"] = [
        sarif_with_rules([], [{"ruleId": "rule-0", "kind": "pass"}])
    ]
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("SUCCESS")
    assert result["failures"] == result["warnings"] == 0


def test_merged_upload_preserves_colliding_rules_and_uri_bases(sast: SastScripts):
    """Cross-tool rule and URI base collisions are renamed in the merged upload."""
    first = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "error"}}],
        [
            {
                "ruleId": "rule-0",
                "ruleIndex": 0,
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "a.py",
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
            }
        ],
        tool="tool-a",
        bases={"%SRCROOT%": {"uri": "file:///a"}},
    )
    second = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [
            {
                "ruleId": "rule-0",
                "ruleIndex": 0,
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "b.py",
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
            }
        ],
        tool="tool-b",
        bases={"%SRCROOT%": {"uri": "file:///b"}},
    )
    sast.case["artifacts"] = [first, second]
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] == 1
    merged = sast.uploaded_sarif()
    assert len(merged["runs"]) == 1
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "rule-0",
        "tool-b/rule-0",
    ]
    first_result, second_result = run["results"]
    assert first_result["ruleId"] == "rule-0"
    assert first_result["ruleIndex"] == 0
    assert (
        first_result["locations"][0]["physicalLocation"]["artifactLocation"][
            "uriBaseId"
        ]
        == "%SRCROOT%"
    )
    assert second_result["ruleId"] == "tool-b/rule-0"
    assert second_result["ruleIndex"] == 1
    assert (
        second_result["locations"][0]["physicalLocation"]["artifactLocation"][
            "uriBaseId"
        ]
        == "tool-b/%SRCROOT%"
    )
    assert run["originalUriBaseIds"] == {
        "%SRCROOT%": {"uri": "file:///a"},
        "tool-b/%SRCROOT%": {"uri": "file:///b"},
    }


def test_merged_upload_rewrites_undeclared_result_rule_ids(sast: SastScripts):
    """A later scanner reusing an undeclared base ruleId gets its own identity."""
    # SARIF does not require a rules entry for every ruleId: a later
    # scanner's result that reuses a base rule id without declaring it must
    # not be attributed to the base scanner's rule.
    base = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "error"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0}],
        tool="tool-a",
    )
    later = sarif_with_rules([], [{"ruleId": "rule-0"}], tool="tool-b")
    sast.case["artifacts"] = [base, later]
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] == 1
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["rule-0"]
    assert [res["ruleId"] for res in run["results"]] == ["rule-0", "tool-b/rule-0"]


def test_merged_upload_reserves_base_result_only_rule_ids(sast: SastScripts):
    """A base result-only ruleId occupies the id, so other tools must be renamed."""
    # A result-only ruleId in the base run occupies the id for its tool: a
    # later scanner reusing it must be renamed instead of sharing the rule
    # identity, while the same tool keeps its own id.
    base = sarif_with_rules([], [{"ruleId": "rule-0", "level": "note"}], tool="tool-a")
    later = sarif_with_rules([], [{"ruleId": "rule-0", "level": "note"}], tool="tool-b")
    repeat = sarif_with_rules(
        [], [{"ruleId": "rule-0", "level": "note"}], tool="tool-a"
    )
    sast.case["artifacts"] = [base, later, repeat]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    assert [res["ruleId"] for res in merged["runs"][0]["results"]] == [
        "rule-0",
        "tool-b/rule-0",
        "rule-0",
    ]


def test_merged_upload_replacement_avoids_incoming_declared_ids(sast: SastScripts):
    """Renamed references avoid colliding with ids the same run declares."""
    # A renamed reference must not collide with an unrelated rule the same
    # run declares; the replacement gets a distinct "#2" suffix instead.
    base = sarif_with_rules(
        [{"id": "rule-0"}], [{"ruleId": "rule-0", "level": "note"}], tool="tool-a"
    )
    later = sarif_with_rules(
        [{"id": "tool-b/rule-0"}],
        [
            {"ruleId": "tool-b/rule-0", "level": "note"},
            {"ruleId": "rule-0", "level": "note"},
        ],
        tool="tool-b",
    )
    sast.case["artifacts"] = [base, later]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "rule-0",
        "tool-b/rule-0",
    ]
    assert [res["ruleId"] for res in run["results"]] == [
        "rule-0",
        "tool-b/rule-0",
        "tool-b/rule-0#2",
    ]


def test_merged_upload_keeps_identical_uri_base_keys(sast: SastScripts):
    """Identical URI base keys across tools are kept unchanged in the merge."""

    def artifact(tool: str, uri: str) -> dict[str, Any]:
        """Build a single-result SARIF document with a shared URI base for a tool."""
        return sarif_with_rules(
            [],
            [
                {
                    "ruleId": "rule-0",
                    "level": "note",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": uri,
                                    "uriBaseId": "%SRCROOT%",
                                }
                            }
                        }
                    ],
                }
            ],
            tool=tool,
            bases={"%SRCROOT%": {"uri": "file:///shared"}},
        )

    sast.case["artifacts"] = [artifact("tool-a", "a.py"), artifact("tool-b", "b.py")]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert run["originalUriBaseIds"] == {"%SRCROOT%": {"uri": "file:///shared"}}
    for result in run["results"]:
        assert (
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"]
            == "%SRCROOT%"
        )


def test_merged_upload_keeps_same_tool_redeclared_rule_id_stable(sast: SastScripts):
    """A same-tool rule re-declaration keeps the id it already owns."""
    # GitHub matches Code Scanning alerts by ruleId across analyses, so a
    # later run from the same tool that re-declares a rule must keep the
    # id it already owns; rewriting it to "tool-a/rule-0" would make an
    # upload containing only the original report split or recreate alerts.
    first = sarif_with_rules(
        [
            {
                "id": "rule-0",
                "shortDescription": {"text": "first declaration"},
                "defaultConfiguration": {"level": "note"},
            }
        ],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    second = sarif_with_rules(
        [
            {
                "id": "rule-0",
                "shortDescription": {"text": "second declaration"},
                "defaultConfiguration": {"level": "note"},
            }
        ],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    sast.case["artifacts"] = [first, second]
    assert sast.run().returncode == 0, sast.logs
    result = sast.assert_result("SUCCESS")
    assert result["failures"] == result["warnings"] == 0
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    # A duplicated rule id makes GitHub reject the upload: exactly one
    # entry survives, and it is the first declaration.
    assert [rule["id"] for rule in rules] == ["rule-0"]
    assert rules[0]["shortDescription"]["text"] == "first declaration"
    assert [res["ruleId"] for res in run["results"]] == ["rule-0", "rule-0"]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 0]


def test_merged_upload_keeps_same_tool_rule_ids_stable_across_repeated_later_runs(
    sast: SastScripts,
):
    """Rule ownership survives the merge loop across repeated later runs."""
    # Rule ownership must survive the merge loop: a rule the same tool
    # declared in an earlier later run is dropped just like one from the
    # base run, so three runs from one tool still yield one entry per id.
    first = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    second = sarif_with_rules(
        [{"id": "rule-1", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-1", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    third = sarif_with_rules(
        [
            {"id": "rule-0", "defaultConfiguration": {"level": "note"}},
            {"id": "rule-1", "defaultConfiguration": {"level": "note"}},
        ],
        [
            {"ruleId": "rule-0", "ruleIndex": 0, "level": "note"},
            {"ruleId": "rule-1", "ruleIndex": 1, "level": "note"},
        ],
        tool="tool-a",
    )
    sast.case["artifacts"] = [first, second, third]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "rule-0",
        "rule-1",
    ]
    assert [res["ruleId"] for res in run["results"]] == [
        "rule-0",
        "rule-1",
        "rule-0",
        "rule-1",
    ]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 1, 0, 1]


def test_merged_upload_appends_new_same_tool_rules_after_redeclared_ones(
    sast: SastScripts,
):
    """A same-tool run appends only its new rules next to re-declared ones."""
    # A same-tool run declaring a new rule next to a re-declared one
    # appends only the new rule; ruleIndex references, with or without a
    # ruleId, resolve to the surviving and the appended entry.
    first = sarif_with_rules(
        [
            {"id": "rule-0", "defaultConfiguration": {"level": "note"}},
            {"id": "rule-1", "defaultConfiguration": {"level": "note"}},
        ],
        [
            {"ruleId": "rule-0", "ruleIndex": 0, "level": "note"},
            {"ruleId": "rule-1", "ruleIndex": 1, "level": "note"},
        ],
        tool="tool-a",
    )
    second = sarif_with_rules(
        [
            {"id": "rule-0", "defaultConfiguration": {"level": "note"}},
            {"id": "rule-2", "defaultConfiguration": {"level": "note"}},
        ],
        [
            {"ruleId": "rule-0", "ruleIndex": 0, "level": "note"},
            {"ruleIndex": 1, "level": "note"},
        ],
        tool="tool-a",
    )
    sast.case["artifacts"] = [first, second]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "rule-0",
        "rule-1",
        "rule-2",
    ]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 1, 0, 2]
    assert [res.get("ruleId") for res in run["results"]] == [
        "rule-0",
        "rule-1",
        "rule-0",
        None,
    ]


def test_merged_upload_rewrites_cross_tool_redeclared_rules_but_keeps_same_tool(
    sast: SastScripts,
):
    """Re-declaration keeps the id for the owning tool but renames other tools."""
    # Ownership is tracked per tool: within one merge a re-declaration by
    # the owning tool keeps the id, while a different tool is still
    # rewritten as "<tool>/<id>" with every reference updated.
    first = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    same_tool = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    other_tool = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-b",
    )
    sast.case["artifacts"] = [first, same_tool, other_tool]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "rule-0",
        "tool-b/rule-0",
    ]
    assert [res["ruleId"] for res in run["results"]] == [
        "rule-0",
        "rule-0",
        "tool-b/rule-0",
    ]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 0, 1]


def test_merged_upload_dedupes_same_tool_rule_declared_twice_within_one_run(
    sast: SastScripts,
):
    """Duplicate declarations within one run resolve to the surviving rule entry."""
    # A run declaring the same id twice, re-declaring the base rule with
    # one of them, must not duplicate the merged entry: both declarations
    # and every ruleIndex pointing at them resolve to the survivor.
    first = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    second = sarif_with_rules(
        [
            {"id": "rule-0", "defaultConfiguration": {"level": "note"}},
            {"id": "rule-0", "defaultConfiguration": {"level": "note"}},
            {"id": "rule-1", "defaultConfiguration": {"level": "note"}},
        ],
        [
            {"ruleId": "rule-0", "ruleIndex": 0, "level": "note"},
            {"ruleId": "rule-0", "ruleIndex": 1, "level": "note"},
            {"ruleId": "rule-1", "ruleIndex": 2, "level": "note"},
        ],
        tool="tool-a",
    )
    sast.case["artifacts"] = [first, second]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "rule-0",
        "rule-1",
    ]
    assert [res["ruleId"] for res in run["results"]] == [
        "rule-0",
        "rule-0",
        "rule-0",
        "rule-1",
    ]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 0, 0, 1]


def test_merged_upload_dedupes_new_rule_id_declared_twice_within_one_run(
    sast: SastScripts,
):
    """A new id declared twice within one run is appended only once."""
    # The same deduplication covers a brand-new id declared twice by one
    # run: only the first declaration is appended, and both ruleIndex
    # references follow it.
    first = sarif_with_rules(
        [{"id": "rule-x", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-x", "ruleIndex": 0, "level": "note"}],
        tool="tool-b",
    )
    second = sarif_with_rules(
        [
            {"id": "rule-1", "defaultConfiguration": {"level": "note"}},
            {"id": "rule-1", "defaultConfiguration": {"level": "note"}},
        ],
        [{"ruleIndex": 0, "level": "note"}, {"ruleIndex": 1, "level": "note"}],
        tool="tool-a",
    )
    sast.case["artifacts"] = [first, second]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "rule-x",
        "rule-1",
    ]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 1, 1]
    assert "ruleId" not in run["results"][1]
    assert "ruleId" not in run["results"][2]


def test_merged_upload_keeps_same_tool_result_only_reference_to_declared_rule(
    sast: SastScripts,
):
    """A same-tool result-only ruleId resolves to the tool's declared rule."""
    # A result-only ruleId from the same tool that declared the rule must
    # not be renamed either: the reference already resolves to the rule
    # the tool owns, and rewriting it would split the rule identity.
    first = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    second = sarif_with_rules(
        [], [{"ruleId": "rule-0", "level": "note"}], tool="tool-a"
    )
    sast.case["artifacts"] = [first, second]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["rule-0"]
    assert [res["ruleId"] for res in run["results"]] == ["rule-0", "rule-0"]


def test_merged_upload_appends_rules_without_id_and_remaps_indices(
    sast: SastScripts,
):
    """Rules without an id are appended and ruleIndex references follow them."""
    # Rules without an id cannot collide and are appended as-is; results
    # referencing them only by ruleIndex must still land on the appended
    # entry.
    first = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    second = sarif_with_rules(
        [
            {"defaultConfiguration": {"level": "note"}},
            {"id": "rule-1", "defaultConfiguration": {"level": "note"}},
        ],
        [{"ruleIndex": 0, "level": "note"}, {"ruleIndex": 1, "level": "note"}],
        tool="tool-a",
    )
    sast.case["artifacts"] = [first, second]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [rule.get("id") for rule in rules] == ["rule-0", None, "rule-1"]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 1, 2]


def test_merged_upload_out_of_range_rule_index_keeps_offset_fallback(
    sast: SastScripts,
):
    """Out-of-range ruleIndex values keep the offset shift; negatives stay put."""
    # ruleIndex values the run never declared (5 with a single rule)
    # cannot follow a rule entry: they keep the historical offset shift,
    # and negative values stay untouched, without corrupting the merge.
    first = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    second = sarif_with_rules(
        [{"id": "rule-1", "defaultConfiguration": {"level": "note"}}],
        [
            {"ruleId": "rule-1", "ruleIndex": 5, "level": "note"},
            {"ruleId": "rule-1", "ruleIndex": -1, "level": "note"},
        ],
        tool="tool-a",
    )
    sast.case["artifacts"] = [first, second]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "rule-0",
        "rule-1",
    ]
    assert [res["ruleId"] for res in run["results"]] == [
        "rule-0",
        "rule-1",
        "rule-1",
    ]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 6, -1]


def test_merged_upload_same_tool_redeclaration_keeps_first_rule_and_gate_failure(
    sast: SastScripts,
):
    """Same-tool re-declaration keeps the first rule while the gate uses the later level."""
    # When the same tool re-declares a rule with different metadata, the
    # first declaration survives in the merged upload while the gate
    # still counts the later file against its own declaration: the level
    # of the level-less result comes from the re-declared rule, so the
    # pipeline fails even though the merged rule keeps the first content.
    first = sarif_with_rules(
        [
            {
                "id": "rule-0",
                "shortDescription": {"text": "first declaration"},
                "defaultConfiguration": {"level": "note"},
            }
        ],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    second = sarif_with_rules(
        [
            {
                "id": "rule-0",
                "shortDescription": {"text": "second declaration"},
                "defaultConfiguration": {"level": "error"},
            }
        ],
        [{"ruleId": "rule-0", "ruleIndex": 0}],
        tool="tool-a",
    )
    sast.case["artifacts"] = [first, second]
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] == 1
    assert result["warnings"] == 0
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["rule-0"]
    assert rules[0]["shortDescription"]["text"] == "first declaration"
    assert rules[0]["defaultConfiguration"]["level"] == "note"
    assert [res["ruleId"] for res in run["results"]] == ["rule-0", "rule-0"]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 0]


def test_merged_upload_reuses_previous_replacement_when_same_tool_redeclares(
    sast: SastScripts,
):
    """A renamed tool keeps reusing its replacement id on later re-declarations."""
    # A tool whose id was renamed after a cross-tool collision keeps
    # using that replacement when it re-declares the id: the rule is
    # dropped against the earlier renamed entry instead of gaining a
    # "#2" suffix, so the tool keeps one stable id per original rule.
    first = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-b",
    )
    second = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    third = sarif_with_rules(
        [{"id": "rule-0", "defaultConfiguration": {"level": "note"}}],
        [{"ruleId": "rule-0", "ruleIndex": 0, "level": "note"}],
        tool="tool-a",
    )
    sast.case["artifacts"] = [first, second, third]
    assert sast.run().returncode == 0, sast.logs
    sast.assert_result("SUCCESS")
    merged = sast.uploaded_sarif()
    run = merged["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "rule-0",
        "tool-a/rule-0",
    ]
    assert [res["ruleId"] for res in run["results"]] == [
        "rule-0",
        "tool-a/rule-0",
        "tool-a/rule-0",
    ]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 1, 1]


def test_no_sarif_artifacts_is_a_legitimate_skip_even_without_a_token(
    sast: SastScripts,
):
    """No SARIF artifacts is a successful skip even when the token is missing."""
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
    """A missing or malformed upload status yields a warning, never a false green."""
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
    """Oddly spelled numeric warning counts stay safe and never turn the result green."""
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
    """An oras discover failure produces a FAILURE result and nonzero exit."""
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
    """An unparseable discovery response fails instead of looking like no artifacts."""
    sast.case["discover_output"] = output
    assert sast.run().returncode == 1, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] >= 1
    assert result["successes"] == 0


@pytest.mark.parametrize("missing", ["IMAGE_URL", "IMAGE_DIGEST"])
def test_missing_image_metadata_still_emits_a_gate_failure(sast: SastScripts, missing):
    """Missing image coordinates still produce a gate failure without uploading."""
    sast.env[missing] = ""
    assert sast.run().returncode == 1, sast.logs
    assert sast.steps["pull-sarif"].returncode != 0
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["failures"] >= 1
    assert not sast.request_path.exists()


def test_unexpected_error_after_artifact_pull_preserves_failure_fallback(
    sast: SastScripts,
):
    """A post-pull collection error keeps the failure fallback and uploads nothing."""
    sast.fail_command("mv")
    assert sast.run().returncode == 1, sast.logs
    # The collection failure is surfaced through the gate rather than by
    # killing the step, so the report still runs and fails the pipeline.
    assert sast.steps["pull-sarif"].returncode == 0, sast.logs
    result = sast.assert_result("FAILURE", exit_code=1)
    assert result["successes"] == 0
    assert result["failures"] >= 1
    assert not sast.request_path.exists()
    assert not (sast.sarif_dir / "merged.sarif.json").exists()
