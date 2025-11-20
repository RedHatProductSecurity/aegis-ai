import pytest
from fastapi.testclient import TestClient

from aegis_ai_web.src import feedback_log
from aegis_ai_web.src.main import app
from tests.utils.llm_cache import get_cached_response, cache_response

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


@pytest.mark.asyncio
async def test_submit_feedback_after_suggest_impact_analysis():
    """
    End-to-end test: Run a suggest-impact analysis then submit feedback based on the results.

    Note: Uses cached LLM responses by default. Set TEST_ALLOW_CAPTURE=true to recapture.
    """
    cve_id = "CVE-2025-23395"
    test_name = "test_submit_feedback_after_suggest_impact_analysis"

    # Step 1: Try to get cached response first
    cached_data = get_cached_response(test_name)

    if cached_data:
        # Use cached response (no LLM costs) - parse JSON string to dict
        import json

        analysis_data = json.loads(cached_data)
    else:
        # Make real API call and cache the response
        analysis_response = client.get(
            f"/api/v1/analysis/cve?feature=suggest-impact&cve_id={cve_id}"
        )
        assert analysis_response.status_code == 200
        analysis_data = analysis_response.json()

        # Cache for future runs - cache as JSON string
        import json

        cache_response(test_name, json.dumps(analysis_data, indent=2))

    # Verify the response contains expected fields
    assert "impact" in analysis_data
    assert analysis_data["cve_id"] == cve_id
    actual_impact = analysis_data["impact"]

    # Verify impact is one of the valid values
    assert actual_impact in ["LOW", "MODERATE", "IMPORTANT", "CRITICAL"]

    # Step 2: Submit feedback based on the analysis results
    # Use a different impact value for the expected field to simulate a correction
    expected_impact = "IMPORTANT" if actual_impact != "IMPORTANT" else "CRITICAL"

    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": cve_id,
        "actual": actual_impact,
        "expected": expected_impact,
        "accept": False,
    }

    feedback_response = client.post("/api/v1/feedback", json=feedback_data)

    # Verify feedback submission was successful
    assert feedback_response.status_code == 200
    assert feedback_response.json() == {
        "status": "Feedback received and logged successfully."
    }

    # Step 3: Verify the feedback was logged correctly
    try:
        with open(feedback_log, "r") as f:
            log_content = f.read()
            assert "feature: 'suggest-impact'" in log_content
            assert f"cve_id: '{cve_id}'" in log_content
            assert f"actual: '{actual_impact}'" in log_content
            assert f"expected: '{expected_impact}'" in log_content
            assert "accept: 'False'" in log_content
    except FileNotFoundError:
        pytest.fail(f"feedback log file was not created at: {feedback_log}")
