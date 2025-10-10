import pytest
from pathlib import Path


@pytest.fixture(autouse=True)
def feedback_log_setup(tmp_path: Path, monkeypatch):
    """
    Create unique temp log file for each test function,
    set AEGIS_WEB_FEEDBACK_LOG env var.

    Note: pytest does automatic cleanup.
    """
    log_file_path = tmp_path / "test_feedback.log"
    monkeypatch.setenv("AEGIS_WEB_FEEDBACK_LOG", str(log_file_path))

    yield log_file_path
