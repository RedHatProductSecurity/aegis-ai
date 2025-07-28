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
