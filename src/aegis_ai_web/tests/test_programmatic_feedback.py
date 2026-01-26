import csv
import pytest
from fastapi.testclient import TestClient

from aegis_ai_web.src.main import app
from aegis_ai_web.src.data_models import PROGRAMMATIC_FEEDBACK_SCHEMA

client = TestClient(app)


def test_save_programmatic_feedback_success(programmatic_feedback_log_setup):
    """
    Test a successful programmatic feedback submission with valid data.
    Acceptance score should be calculated server-side (None for non-matching values).
    """
    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-23395",
        "email": "joey@redhat.com",
        "suggested_value": "CRITICAL",
        "submitted_value": "HIGH",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 200
    assert response.json() == {
        "status": "Programmatic feedback received and logged successfully."
    }

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) > 0, "No rows found in programmatic feedback log"
            last_row = rows[-1]
            assert last_row["feature"] == "suggest-impact"
            assert last_row["cve_id"] == "CVE-2025-23395"
            assert last_row["email"] == "joey@redhat.com"
            assert last_row["suggested_value"] == "CRITICAL"
            assert last_row["submitted_value"] == "HIGH"
            # Non-matching values should result in empty acceptance_score
            assert last_row["acceptance_score"] == ""
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_exact_match(programmatic_feedback_log_setup):
    """
    Test programmatic feedback when suggested and submitted values match.
    Backend should calculate acceptance_score as 1.0.
    """
    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-23395",
        "suggested_value": "CRITICAL",
        "submitted_value": "CRITICAL",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 200

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            last_row = rows[-1]
            assert last_row["suggested_value"] == "CRITICAL"
            assert last_row["submitted_value"] == "CRITICAL"
            # Exact match should result in acceptance_score of 1.0
            assert last_row["acceptance_score"] == "1.0"
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_empty_suggested_value(
    programmatic_feedback_log_setup,
):
    """
    Test programmatic feedback with empty suggested value.
    Backend should calculate acceptance_score as empty (None).
    """
    feedback_data = {
        "feature": "suggest-cwe",
        "cve_id": "CVE-2025-12345",
        "email": "user@example.com",
        "suggested_value": "",
        "submitted_value": "CWE-89",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 200

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) > 0, "No rows found in programmatic feedback log"
            last_row = rows[-1]
            assert last_row["feature"] == "suggest-cwe"
            # Empty suggested value should result in empty acceptance_score
            assert last_row["acceptance_score"] == ""
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_empty_submitted_value(
    programmatic_feedback_log_setup,
):
    """
    Test programmatic feedback with empty submitted value.
    Backend should calculate acceptance_score as empty (None).
    """
    feedback_data = {
        "feature": "suggest-cwe",
        "cve_id": "CVE-2025-12345",
        "suggested_value": "CWE-79",
        "submitted_value": "",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 200

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) > 0
            last_row = rows[-1]
            # Empty submitted value should result in empty acceptance_score
            assert last_row["acceptance_score"] == ""
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_validation_error_missing_feature():
    """
    Test request with missing required feature field.
    """
    feedback_data = {
        "cve_id": "CVE-2025-23395",
        "suggested_value": "CRITICAL",
        "submitted_value": "HIGH",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 422


def test_save_programmatic_feedback_rejects_acceptance_score_in_payload():
    """
    Test that sending acceptance_score in payload is ignored (not validated).
    The backend calculates acceptance_score server-side, so any client-provided
    value should be disregarded.
    """
    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-23395",
        "suggested_value": "CRITICAL",
        "submitted_value": "HIGH",
        "acceptance_score": 0.85,  # This should be ignored
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    # Request should succeed (extra fields are ignored by Pydantic by default)
    assert response.status_code == 200


def test_save_programmatic_feedback_allows_duplicate_submissions(
    programmatic_feedback_log_setup,
):
    """
    Test that duplicate programmatic feedback submissions are allowed at write time.
    Deduplication happens at KPI read time, not at write time.
    """
    feedback_data = {
        "feature": "suggest-cwe",
        "cve_id": "CVE-2025-14322",
        "email": "user@example.com",
        "suggested_value": "CWE-193",
        "submitted_value": "CWE-501",
    }

    # First submission should succeed
    response1 = client.post("/api/v1/programmatic-feedback", json=feedback_data)
    assert response1.status_code == 200

    # Second identical submission should also succeed (deduplication at read time)
    response2 = client.post("/api/v1/programmatic-feedback", json=feedback_data)
    assert response2.status_code == 200

    # Both entries are written to the log (deduplication happens at KPI read time)
    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            matching_rows = [
                r
                for r in rows
                if r["feature"] == "suggest-cwe"
                and r["cve_id"] == "CVE-2025-14322"
                and r["email"] == "user@example.com"
            ]
            assert len(matching_rows) == 2, "Expected two entries in log"
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_allows_different_submitted_value(
    programmatic_feedback_log_setup,
):
    """
    Test that submissions with different submitted_value are allowed (not duplicates).
    """
    base_feedback = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-99999",
        "email": "user@example.com",
        "suggested_value": "CRITICAL",
    }

    # First submission
    response1 = client.post(
        "/api/v1/programmatic-feedback",
        json={**base_feedback, "submitted_value": "HIGH"},
    )
    assert response1.status_code == 200

    # Second submission with different submitted_value should succeed
    response2 = client.post(
        "/api/v1/programmatic-feedback",
        json={**base_feedback, "submitted_value": "MODERATE"},
    )
    assert response2.status_code == 200


def test_save_programmatic_feedback_csv_schema_fields(programmatic_feedback_log_setup):
    """
    Test that CSV log has all expected schema fields.
    """
    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-23395",
        "email": "test@example.com",
        "suggested_value": "CRITICAL",
        "submitted_value": "HIGH",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)
    assert response.status_code == 200

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) > 0
            last_row = rows[-1]
            # Validate against schema fields
            expected_fields = set(PROGRAMMATIC_FEEDBACK_SCHEMA.field_names)
            assert set(last_row.keys()) == expected_fields, (
                "CSV row fields don't match schema"
            )
            # Check auto-populated fields
            assert last_row["datetime"] != ""  # Should be auto-populated
            assert last_row["version"] != ""  # Should be auto-populated
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )
