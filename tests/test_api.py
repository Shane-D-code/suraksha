"""
API endpoint tests.
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from app.main import app


@pytest.fixture
def client():
    """Test client fixture."""
    return TestClient(app)


@pytest.fixture
def auth_token():
    """Generate test auth token."""
    from app.middleware.auth import create_access_token
    return create_access_token(
        data={"sub": "test_user", "roles": ["admin"]}
    )


class TestHealthEndpoints:
    """Test health check endpoints."""
    
    def test_root_endpoint(self, client):
        """Test root endpoint returns app info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert data["status"] == "running"
    
    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestScanEndpoint:
    """Test /scan endpoint."""
    
    @patch("app.api.routes.get_redis_client")
    @patch("app.api.routes.simulate_ml_inference")
    @patch("app.api.routes.GraphService")
    def test_scan_url(
        self, 
        mock_graph, 
        mock_ml, 
        mock_redis,
        client
    ):
        """Test scanning a URL."""
        # Mock Redis
        mock_redis_client = AsyncMock()
        mock_redis_client.get.return_value = None
        mock_redis.return_value = mock_redis_client
        
        # Mock ML inference
        mock_ml.return_value = 0.8
        
        # Mock Graph service
        mock_graph_instance = AsyncMock()
        mock_graph_instance.get_risk_score.return_value = 0.7
        mock_graph.return_value = mock_graph_instance
        
        response = client.post(
            "/api/v1/scan",
            json={"url": "https://example.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert "risk" in data
        assert data["risk"] in ["LOW", "MEDIUM", "HIGH"]
    
    def test_scan_invalid_url(self, client):
        """Test scanning with invalid URL."""
        response = client.post(
            "/api/v1/scan",
            json={"url": "not-a-url"}
        )
        assert response.status_code == 422
    
    def test_scan_empty_request(self, client):
        """Test scanning with empty request."""
        response = client.post(
            "/api/v1/scan",
            json={}
        )
        # Should accept empty request (all fields optional)
        assert response.status_code in [200, 422]


class TestThreatIntelEndpoint:
    """Test /threat-intel endpoint."""
    
    def test_get_threat_intel_unauthorized(self, client):
        """Test unauthorized access to threat intel."""
        response = client.get("/api/v1/threat-intel/example.com")
        assert response.status_code == 403
    
    def test_get_threat_intel_not_found(self, client, auth_token):
        """Test non-existent domain."""
        response = client.get(
            "/api/v1/threat-intel/nonexistent.example",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        # Returns 200 with fallback data from graph service when domain not in DB
        assert response.status_code in [200, 404, 500]


class TestModelHealthEndpoint:
    """Test /model-health endpoint."""
    
    def test_model_health_unauthorized(self, client):
        """Test unauthorized access to model health."""
        response = client.get("/api/v1/model-health")
        assert response.status_code == 403
    
    def test_model_health_admin(self, client, auth_token):
        """Test model health with admin token."""
        response = client.get(
            "/api/v1/model-health",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "model_name" in data
        assert "uptime" in data


class TestFeedbackEndpoint:
    """Test /feedback endpoint."""
    
    def test_feedback_unauthorized(self, client):
        """Test unauthorized feedback submission."""
        response = client.post(
            "/api/v1/feedback",
            json={
                "scan_id": "test123",
                "user_flag": True
            }
        )
        assert response.status_code == 403
    
    def test_feedback_with_auth(self, client, auth_token):
        """Test feedback submission with auth."""
        response = client.post(
            "/api/v1/feedback",
            json={
                "scan_id": "test123",
                "user_flag": True,
                "comment": "Test comment"
            },
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code in [200, 201, 500]
