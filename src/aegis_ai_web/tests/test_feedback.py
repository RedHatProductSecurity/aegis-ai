import pytest
from fastapi.testclient import TestClient

from aegis_ai_web.src import feedback_log
from aegis_ai_web.src.main import app

client = TestClient(app)


def test_save_feedback_success():
    """
    Test a successful feedback submission with valid data.
    """

    feedback_data = {
        "feature": "suggest-cwe",
        "cve_id": "CVE-2025-23395",
        "email": "joey@redhat.com",
        "actual": "CWE-120",
        "accept": "true",
    }
    response = client.post("/api/v1/feedback", json=feedback_data)

    assert response.status_code == 200
    assert response.json() == {"status": "Feedback received and logged successfully."}

    try:
        with open(feedback_log, "r") as f:
            log_content = f.read()
            assert "feature: 'suggest-cwe'" in log_content
    except FileNotFoundError:
        pytest.fail(f"feedback log file was not created at: {feedback_log}")


def test_save_feedback_sanitization():
    """
    Test simple sanitization.
    """

    feedback_data = {
        "feature": "suggest-cwe",
        "cve_id": "CVE-2025-23395",
        "email": "joey@redhat.com",
        "actual": "Trying to inject a\nnewline",
        "accept": "true",
    }
    response = client.post("/api/v1/feedback", json=feedback_data)
    assert response.status_code == 200

    try:
        with open(feedback_log, "r") as f:
            log_content = f.read()
            assert "Trying to inject anewline" in log_content
            assert "feature: 'suggest-cwe'" in log_content
    except FileNotFoundError:
        pytest.fail(f"feedback log file was not created at: {feedback_log}")


def test_save_feedback_validation_error_missing_field():
    """
    Test request with missing required field.
    """
    feedback_data = {
        # should have feature key
        "cve_id": "CVE-2025-23395",
        "email": "joey@redhat.com",
        "actual": "Trying to inject a\nnewline.",
        "accept": "true",
    }
    response = client.post("/api/v1/feedback", json=feedback_data)

    assert response.status_code == 422


def test_save_feedback_validation_error_bad_accept():
    """
    Test request with missing required field.
    """
    feedback_data = {
        "feature": "suggest-cwe",
        "cve_id": "CVE-2025-23395",
        "email": "joey@redhat.com",
        "actual": "CWE-120",
        "accept": "someincorrectvalue",
    }
    response = client.post("/api/v1/feedback", json=feedback_data)
    assert response.status_code == 422
