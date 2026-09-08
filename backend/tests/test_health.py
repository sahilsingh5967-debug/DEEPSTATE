from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_top_level_health_endpoint():
    """Test top-level GET /health returns HTTP 200 OK and valid status schema."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "timestamp" in data


def test_v1_health_endpoint():
    """Test GET /api/v1/health returns HTTP 200 OK and valid status schema."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "timestamp" in data
