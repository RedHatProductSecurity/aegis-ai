import pytest
import yaml
from fastapi.testclient import TestClient

from aegis_ai_web.src.main import app

# Create a TestClient instance based on your FastAPI app
client = TestClient(app)


def test_read_root():
    """
    Test the root endpoint to ensure it returns a 200 OK status.
    """
    response = client.get("/")
    assert response.status_code == 200


def test_yaml_openapi():
    """
    Test the root endpoint to ensure it returns a 200 OK status.
    """
    response = client.get("/openapi.yml")
    assert response.status_code == 200
    assert "application/vnd.oai.openapi" in response.headers["content-type"]
    try:
        openapi_spec = yaml.safe_load(response.text)
    except yaml.YAMLError:
        assert False, "Response is not valid YAML"

    assert isinstance(openapi_spec, dict)
    assert "openapi" in openapi_spec
    assert "info" in openapi_spec
    assert "paths" in openapi_spec

    assert openapi_spec["info"]["title"] == "Aegis REST-API"


@pytest.mark.parametrize(
    "invalid_json_content,description",
    [
        ("invalid json content", "completely invalid JSON"),
        ('{"cve_id": "CVE-2025-12345"', "malformed JSON (missing closing brace)"),
        ("", "empty body"),
    ],
)
def test_invalid_json_request_body(invalid_json_content, description):
    """
    Test that invalid JSON in request body returns 400 with proper error message
    instead of leaking a full traceback.
    """
    response = client.post(
        "/api/v1/analysis/cve/suggest-impact",
        content=invalid_json_content,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert "detail" in response.json()
    assert "Invalid JSON" in response.json()["detail"]
    # Verify traceback is not present in response
    assert "Traceback" not in response.text
    assert "stack" not in response.text


def test_missing_cve_id_field():
    """
    Test that missing 'cve_id' field in request body returns 400 with proper error message
    instead of leaking a full traceback.
    """
    response = client.post(
        "/api/v1/analysis/cve/suggest-impact",
        json={},  # Empty JSON body - missing 'cve_id' field
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert "detail" in response.json()
    assert "Missing required field: 'cve_id'" in response.json()["detail"]
    # Verify traceback is not present in response
    assert "Traceback" not in response.text
    assert "stack" not in response.text


def test_invalid_utf8_encoding():
    """
    Test that invalid UTF-8 encoding in request body returns 400 with proper error message
    instead of leaking a full traceback.

    Note: This test sends raw bytes with invalid UTF-8. The UnicodeDecodeError may occur
    during body reading or JSON parsing, but should be caught by the global handler.
    """
    # Create invalid UTF-8 bytes (invalid continuation byte \x80)
    # This simulates the curl example: curl -d $'{\x80'
    invalid_utf8 = b"{\x80"
    response = client.post(
        "/api/v1/analysis/cve/suggest-impact",
        content=invalid_utf8,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert "detail" in response.json()
    # The error might be caught as JSONDecodeError or UnicodeDecodeError
    # depending on when the encoding error occurs
    detail = response.json()["detail"]
    assert "Invalid" in detail and (
        "JSON" in detail or "UTF-8" in detail or "encoding" in detail
    )
    # Verify traceback is not present in response
    assert "Traceback" not in response.text
    assert "stack" not in response.text
