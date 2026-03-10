"""Pytest hooks and fixtures for CVE evals (e.g. suggest-affected-components)."""


def pytest_addoption(parser):
    """Register --sample for suggest-affected-components eval."""
    parser.addoption(
        "--sample",
        type=int,
        default=None,
        help="Suggest-affected-components eval: randomly sample N cases (default: use all).",
    )
