"""Pytest hooks and fixtures for CVE evals.

Covers suggest-impact, suggest-cwe, suggest-description, suggest-statement,
suggest-affected-components, identify-pii, and cvss-diff. See evals under
``evals/features/cve/``; rubrics are aligned with AEGIS-333 human feedback
(CVSS PR/S/CIA for kernel issues, statement severity rationale, title/description
concision).
"""

import warnings
from pathlib import Path

import pytest

_EVAL_DIR = Path(__file__).resolve().parent
_CVE_LIST = _EVAL_DIR / "kernel_eval_cves.txt"
_EVAL_CSV = _EVAL_DIR / "eval-kernel-cves.csv"


def pytest_addoption(parser):
    """Register --sample for suggest-affected-components eval."""
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


@pytest.fixture(autouse=True, scope="session")
def _check_kernel_eval_csv():
    """Ensure eval-kernel-cves.csv exists and is not stale.

    The CSV is generated from kernel_eval_cves.txt by
    ``generate_kernel_eval_csv.py``.  If the text file is newer than the
    CSV, the ground-truth data may be out of date.
    """
    if not _EVAL_CSV.exists():
        pytest.fail(
            f"{_EVAL_CSV.name} not found. Generate it:\n  make prepare-kernel-eval"
        )

    if _CVE_LIST.exists() and _CVE_LIST.stat().st_mtime > _EVAL_CSV.stat().st_mtime:
        warnings.warn(
            f"{_EVAL_CSV.name} is older than {_CVE_LIST.name} — ground truth may be stale.\n"
            "Regenerate with:  make prepare-kernel-eval",
            stacklevel=1,
        )
