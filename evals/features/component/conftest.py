"""Pytest hooks and fixtures for the component intelligence eval suite."""

import os
from pathlib import Path

import pytest

# Curated CVE list for component intel (novel ecosystems, github.com, special chars)
# conftest is at evals/features/component/; parents[2] = evals/; file is evals/component_intel_cve_ids.txt
_COMPONENT_INTEL_CURATED_FILE = (
    Path(__file__).resolve().parents[2] / "component_intel_cve_ids.txt"
)


def _load_curated_cve_ids() -> set[str] | None:
    """Load curated CVE IDs from component_intel_cve_ids.txt. Returns None if file missing."""
    if not _COMPONENT_INTEL_CURATED_FILE.is_file():
        return None
    cves = set()
    for line in _COMPONENT_INTEL_CURATED_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            cves.add(line)
    return cves if cves else None


def pytest_addoption(parser):
    """Register --sample for component intelligence eval."""
    parser.addoption(
        "--sample",
        type=int,
        default=None,
        help="Component intelligence eval: randomly sample N cases from component_intel_cve_ids.txt (default: use all).",
    )


@pytest.fixture(scope="session")
def component_intel_sample_size(request):
    """Sample size for component intelligence cases: --sample N or COMPONENT_INTEL_EVAL_SAMPLE env."""
    import os

    cli = getattr(request.config.option, "sample", None)
    env_val = os.getenv("COMPONENT_INTEL_EVAL_SAMPLE")
    if cli is not None:
        return cli
    if env_val is not None:
        try:
            return int(env_val)
        except ValueError:
            return None
    return None


@pytest.fixture(scope="session")
def component_intel_cve_ids(component_intel_sample_size):
    """Set of CVE IDs for component intelligence eval.
    When --sample / COMPONENT_INTEL_EVAL_SAMPLE is set, always use curated list (sample only from it).
    Otherwise: COMPONENT_INTEL_EVAL_CVE_IDS env, or curated file, or None (all qualifying cache)."""
    if component_intel_sample_size is not None:
        # Sampling: only draw from curated list (avoids kernel/PoC cases that trigger safety filters)
        curated = _load_curated_cve_ids()
        if curated:
            return curated
        # Curated file missing; fall back to env or None
    raw = os.getenv("COMPONENT_INTEL_EVAL_CVE_IDS", "").strip()
    if raw:
        return {cve_id.strip() for cve_id in raw.split(",") if cve_id.strip()}
    return _load_curated_cve_ids()
