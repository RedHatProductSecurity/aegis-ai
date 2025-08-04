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
