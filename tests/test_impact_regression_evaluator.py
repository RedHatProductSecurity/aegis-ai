"""Deterministic checks for the AEGIS-545 assertions and their real cached evidence."""

import csv
from pathlib import Path

import pytest
from pydantic_evals import Case, Dataset

from aegis_ai.features.cve import SuggestImpactModel
from aegis_ai.toolsets.tools.osv_common import filter_osv_response
from evals.features.common import MIN_SCORE_THRESHOLD, handle_eval_report
from evals.features.cve.test_suggest_impact import (
    CVSSScoreEvaluator,
    CVSSValidator,
    CVSSVectorEvaluator,
    ImpactEvaluator,
    KernelImpactRegressionEvaluator,
    kernel_memory_regression_cases,
)
from evals.utils import (
    external_references_cache,
    ghsa_cache,
    kernel_cve_context_cache,
    kernel_patch_cache,
    osidb_cache,
)

pytestmark = pytest.mark.asyncio

ROOT = Path(__file__).resolve().parents[1]
REGRESSION_CVE = "CVE-2026-98432"
EXPECTED_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
OLD_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"


def _case(cve_id):
    return next(c for c in kernel_memory_regression_cases if c.inputs == cve_id)


@pytest.fixture
def expected_output() -> SuggestImpactModel:
    expected = _case(REGRESSION_CVE).expected_output
    assert isinstance(expected, SuggestImpactModel)
    return expected


async def _evaluate(output, expected, evaluators=None):
    async def predict(_cve_id):
        return output

    dataset = Dataset(
        name="kernel-impact-regression",
        cases=[
            Case(
                name="kernel-regression",
                inputs=output.cve_id,
                expected_output=expected,
            )
        ],
        evaluators=evaluators
        or [
            evaluator
            for evaluator in _case(output.cve_id).evaluators
            if isinstance(evaluator, KernelImpactRegressionEvaluator)
        ],
    )
    report = await dataset.evaluate(predict, progress=False)
    assert not report.failures
    assert len(report.cases) == 1
    assert not report.cases[0].evaluator_failures
    return report


def _assertion(report):
    return report.cases[0].assertions["KernelImpactRegressionEvaluator"]


@pytest.mark.parametrize(
    "case", kernel_memory_regression_cases, ids=lambda case: case.inputs
)
async def test_accepts_expected_metrics_and_impact_even_with_low_confidence(case):
    expected = case.expected_output
    output = expected.model_copy(
        update={"confidence": 0.0, "impact": expected.impact or "IMPORTANT"}
    )
    report = await _evaluate(output, expected)
    assert _assertion(report).value is True
    assert not report.cases[0].scores


async def test_accepts_equivalent_vector_metric_order(expected_output):
    output = expected_output.model_copy(
        update={"cvss3_vector": "CVSS:3.1/C:H/I:H/A:H/S:U/UI:N/PR:N/AC:L/AV:N"}
    )
    assert _assertion(await _evaluate(output, expected_output)).value is True


@pytest.mark.parametrize(
    ("vector", "metric"),
    [
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "AC"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H", "C"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", "C"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H", "I"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", "I"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", "A"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "A"),
    ],
)
async def test_rejects_each_regressed_metric(vector, metric, expected_output):
    output = expected_output.model_copy(update={"cvss3_vector": vector})
    result = _assertion(await _evaluate(output, expected_output))
    assert result.value is False
    assert result.reason
    assert f"{metric}:" in result.reason


@pytest.mark.parametrize("impact", ["IMPORTANT", "MODERATE", "LOW", None])
async def test_rejects_underestimated_or_missing_impact(impact, expected_output):
    output = expected_output.model_copy(update={"impact": impact})
    result = _assertion(await _evaluate(output, expected_output))
    assert result.value is False
    assert result.reason
    assert "impact:" in result.reason
    assert "CRITICAL" in result.reason


@pytest.mark.parametrize(
    "vector",
    [
        None,
        "",
        "not-a-vector",
        "CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",  # missing AC
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:Z/I:H/A:H",
        "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
async def test_fails_closed_for_missing_or_invalid_vector(vector, expected_output):
    # model_copy deliberately bypasses DTO validation to exercise the evaluator's
    # failure handling, including outputs without a vector (which the DTO permits).
    output = expected_output.model_copy(update={"cvss3_vector": vector})
    result = _assertion(await _evaluate(output, expected_output))
    assert result.value is False
    assert result.reason
    assert "vector" in result.reason


@pytest.mark.parametrize("vector", [None, "", "invalid"])
async def test_fails_closed_for_missing_or_invalid_expectation(vector, expected_output):
    expected = expected_output.model_copy(update={"cvss3_vector": vector})
    result = _assertion(await _evaluate(expected_output, expected))
    assert result.value is False
    assert result.reason
    assert "vector" in result.reason


async def test_fails_closed_without_expected_output(expected_output):
    result = _assertion(await _evaluate(expected_output, None))
    assert result.value is False
    assert result.reason
    assert "expected CVSS vector" in result.reason


@pytest.mark.parametrize("cve_id", ["CVE-2022-50865", "CVE-2023-53733"])
@pytest.mark.parametrize(
    ("metric", "value"), [("C", "L"), ("C", "H"), ("I", "L"), ("I", "H")]
)
async def test_rejects_invented_kernel_memory_impact_for_negative_controls(
    cve_id, metric, value
):
    expected = _case(cve_id).expected_output
    vector = expected.cvss3_vector.replace(f"/{metric}:N", f"/{metric}:{value}")
    output = expected.model_copy(update={"cvss3_vector": vector})
    result = _assertion(await _evaluate(output, expected))
    assert result.value is False
    assert result.reason
    assert f"{metric}: got {value}, expected N" in result.reason


@pytest.mark.parametrize(
    ("cve_id", "vector", "score", "impact"),
    [
        (
            "CVE-2022-50865",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "7.5",
            "IMPORTANT",
        ),
        (
            "CVE-2022-50865",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "5.9",
            "MODERATE",
        ),
        (
            "CVE-2023-53733",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
            "3.3",
            "LOW",
        ),
    ],
)
async def test_control_calibration_differences_remain_visible_as_soft_scores(
    cve_id, vector, score, impact
):
    case = _case(cve_id)
    expected = case.expected_output
    output = expected.model_copy(
        update={"cvss3_vector": vector, "cvss3_score": score, "impact": impact}
    )
    evaluators = [
        evaluator
        for evaluator in case.evaluators
        if isinstance(
            evaluator,
            (
                KernelImpactRegressionEvaluator,
                ImpactEvaluator,
                CVSSScoreEvaluator,
                CVSSVectorEvaluator,
            ),
        )
    ]
    report = await _evaluate(
        output, expected, evaluators=evaluators + [CVSSValidator()]
    )
    assert _assertion(report).value is True
    assert report.cases[0].assertions["CVSSValidator"].value is True
    assert set(report.cases[0].scores) == {
        "ImpactEvaluator",
        "CVSSScoreEvaluator",
        "CVSSVectorEvaluator",
    }
    assert all(score.value < 1 for score in report.cases[0].scores.values())


@pytest.mark.parametrize("cve_id", ["CVE-2022-50865", "CVE-2023-53733"])
@pytest.mark.parametrize("vector", [None, "invalid"])
async def test_controls_also_fail_closed_for_missing_or_invalid_vectors(cve_id, vector):
    expected = _case(cve_id).expected_output
    output = expected.model_copy(update={"cvss3_vector": vector})
    result = _assertion(await _evaluate(output, expected))
    assert result.value is False
    assert result.reason
    assert "vector" in result.reason


async def test_old_assessment_fails_report_even_when_all_soft_scores_pass(
    expected_output, caplog
):
    output = expected_output.model_copy(
        update={"cvss3_vector": OLD_VECTOR, "cvss3_score": "5.9", "impact": "MODERATE"}
    )
    report = await _evaluate(
        output,
        expected_output,
        evaluators=[
            KernelImpactRegressionEvaluator(),
            ImpactEvaluator(),
            CVSSScoreEvaluator(),
            CVSSVectorEvaluator(),
            CVSSValidator(),
        ],
    )
    case = report.cases[0]
    assert all(score.value >= MIN_SCORE_THRESHOLD for score in case.scores.values())
    assert case.assertions["CVSSValidator"].value is True
    result = _assertion(report)
    assert result.value is False
    assert result.reason
    for mismatch in ("AC:", "C:", "I:", "impact:"):
        assert mismatch in result.reason
    with (
        caplog.at_level("WARNING", logger="evals.features.common"),
        pytest.raises(AssertionError, match="KernelImpactRegressionEvaluator"),
    ):
        handle_eval_report(report)


@pytest.fixture
def local_eval_caches(monkeypatch):
    """Pin cache reads to this worktree and reject any live cache-miss fallback."""
    monkeypatch.setattr(osidb_cache, "OSIDB_CACHE_DIR", ROOT / "evals/osidb_cache")
    monkeypatch.setattr(
        kernel_cve_context_cache,
        "KERNEL_CVE_CACHE_DIR",
        ROOT / "evals/kernel_cve_context_cache",
    )
    monkeypatch.setattr(
        kernel_patch_cache, "KERNEL_PATCH_CACHE_DIR", ROOT / "evals/kernel_patch_cache"
    )
    monkeypatch.setattr(
        external_references_cache, "CACHE_DIR", ROOT / "evals/external_references_cache"
    )
    monkeypatch.setattr(ghsa_cache, "GHSA_CACHE_DIR", ROOT / "evals/ghsa_cache")

    def reject_live_fetch(*_args, **_kwargs):
        pytest.fail(
            "kernel regression evidence must be available from checked-in caches"
        )

    monkeypatch.setattr(osidb_cache, "cve_retrieve", reject_live_fetch)
    monkeypatch.setattr(
        external_references_cache, "live_fetch_reference", reject_live_fetch
    )
    monkeypatch.setattr(ghsa_cache.OSVClient, "get_vuln_by_id", reject_live_fetch)


@pytest.mark.parametrize(
    "case", kernel_memory_regression_cases, ids=lambda case: case.inputs
)
async def test_regression_tool_evidence_is_complete_and_offline(
    case, local_eval_caches
):
    flaw = await osidb_cache.osidb_cache_retrieve(case.inputs)
    assert flaw.status == "success"
    assert "kernel" in flaw.components
    context = await kernel_cve_context_cache.kernel_cve_cache_lookup(case.inputs)
    assert context.metadata is not None
    assert context.metadata.json_data
    assert context.metadata.mbox_data
    identity = context.metadata.json_data["cveMetadata"]
    assert identity.get("cveId", identity.get("cveID")) == case.inputs
    assert case.inputs in context.metadata.mbox_data
    assert "Anubis" not in context.metadata.mbox_data
    hashes = [url.rsplit("/", 1)[-1] for url in context.metadata.commit_hashes]
    assert hashes
    patches = await kernel_patch_cache.cached_fetch_patches(None, hashes)
    text = await kernel_patch_cache.cached_fetch_commit_html(None, hashes)
    assert {h for h, _ in patches} == set(hashes)
    assert {h for h, _ in text} == set(hashes)
    for commit_hash, patch in patches:
        assert patch.startswith(f"From {commit_hash} ")
        assert "diff --git" in patch
    for _, content in patches + text:
        assert "Anubis" not in content
    assert flaw.references
    for reference in flaw.references:
        result = await external_references_cache.extref_cache_retrieve(reference["url"])
        assert result.status == "success"
        assert result.extracted_text and case.inputs in result.extracted_text
        assert "Anubis" not in result.extracted_text


async def test_new_case_and_kernel_ground_truth_match_captured_cna(
    expected_output, local_eval_caches
):
    context = await kernel_cve_context_cache.kernel_cve_cache_lookup(REGRESSION_CVE)
    assert context.metadata is not None
    assert context.metadata.json_data is not None
    cna = context.metadata.json_data["containers"]["cna"]
    metric = cna["metrics"][0]["cvssV3_1"]
    assert set(context.metadata.commit_hashes) == {
        reference["url"] for reference in cna["references"]
    }
    assert len(context.metadata.commit_hashes) == 8
    flaw = await osidb_cache.osidb_cache_retrieve(REGRESSION_CVE)
    assert expected_output.cvss3_vector == metric["vectorString"] == EXPECTED_VECTOR
    assert float(expected_output.cvss3_score) == metric["baseScore"] == 9.8
    assert expected_output.impact == flaw.impact == metric["baseSeverity"] == "CRITICAL"
    assert all(score["vector"] == EXPECTED_VECTOR for score in flaw.cvss_scores)
    assert {score["issuer"] for score in flaw.cvss_scores} == {"RH", "CVEORG"}
    with (ROOT / "evals/features/cve/eval-kernel-cves.csv").open(newline="") as source:
        rows = [row for row in csv.DictReader(source) if row["CVE"] == REGRESSION_CVE]
    assert len(rows) == 1
    assert rows[0]["OSIDB Impact"].upper() == "CRITICAL"
    assert float(rows[0]["OSIDB CVSS"]) == 9.8
    assert rows[0]["OSIDB CVSS Vector"] == EXPECTED_VECTOR
    assert not (_case(REGRESSION_CVE).metadata or {}).get("known_to_fail_evaluators")


async def test_new_osv_evidence_is_offline_and_matches_the_cna(local_eval_caches):
    raw = await ghsa_cache.ghsa_cache_retrieve(REGRESSION_CVE)
    filtered = filter_osv_response(raw)
    context = await kernel_cve_context_cache.kernel_cve_cache_lookup(REGRESSION_CVE)
    assert context.metadata is not None
    assert context.metadata.json_data is not None
    cna = context.metadata.json_data["containers"]["cna"]
    assert raw["id"] == filtered["id"] == REGRESSION_CVE
    assert filtered["summary"] == cna["title"]
    assert filtered["details"] == cna["descriptions"][0]["value"]
    assert filtered["database_specific"]["cna_assigner"] == "Linux"
    assert raw["severity"] == [{"type": "CVSS_V3", "score": EXPECTED_VECTOR}]
    fixed = {
        event["fixed"]
        for affected in filtered["affected"]
        for version_range in affected.get("ranges", [])
        if version_range["type"] == "GIT"
        for event in version_range["events"]
        if "fixed" in event
    }
    assert fixed == {url.rsplit("/", 1)[-1] for url in context.metadata.commit_hashes}
