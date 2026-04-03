"""Pytest hooks and fixtures for CVE evals.

Covers suggest-impact, suggest-cwe, suggest-description, suggest-statement,
suggest-affected-components, identify-pii, and cvss-diff. See evals under
``evals/features/cve/``; rubrics are aligned with AEGIS-333 human feedback
(CVSS PR/S/CIA for kernel issues, statement severity rationale, title/description
concision).
"""


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
