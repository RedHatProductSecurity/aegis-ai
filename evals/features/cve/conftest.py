"""Pytest hooks and fixtures for CVE evals.

Covers suggest-impact, suggest-cwe, suggest-description, suggest-statement,
suggest-affected-components, identify-pii, and cvss-diff. See evals under
``evals/features/cve/``; rubrics are aligned with AEGIS-333 human feedback
(CVSS PR/S/CIA for kernel issues, statement severity rationale, title/description
concision).
"""

from pathlib import Path

import pytest

_EVAL_DIR = Path(__file__).resolve().parent
_EVAL_CSV = _EVAL_DIR / "eval-kernel-cves.csv"


def pytest_addoption(parser):
    """Register focused-run and reporting options for CVE evals."""
    parser.addoption(
        "--sample",
        type=int,
        default=None,
        help="Suggest-affected-components eval: randomly sample N cases (default: use all).",
    )
    parser.addoption(
        "--audit",
        action="store_true",
        default=False,
        help="Run post-eval audit after kernel eval and write kernel_eval_audit.json.",
    )
    parser.addoption(
        "--kernel-memory-regressions-only",
        action="store_true",
        default=False,
        help="Suggest-impact eval: run only the AEGIS-545 kernel memory/race regressions and controls.",
    )


@pytest.fixture(autouse=True, scope="session")
def _check_kernel_eval_csv():
    """Ensure eval-kernel-cves.csv exists."""
    if not _EVAL_CSV.exists():
        pytest.fail(
            f"{_EVAL_CSV.name} not found. Generate it:\n  make prepare-kernel-eval"
        )
