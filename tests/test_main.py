import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from uuid import uuid4
from unittest.mock import patch, MagicMock
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def create_test_app():
    test_env = {
        'REDIS_URL': 'redis://fake',
        'API_RATE_LIMIT_TIMES': '5',
        'API_RATE_LIMIT_SECONDS': '10',
        'ANOMALY_ALERT_THRESHOLD': '0.8',
    }

    with patch.dict(os.environ, test_env):
        with patch('fastapi_limiter.FastAPILimiter.init', return_value=None):
            with patch('fastapi_limiter.FastAPILimiter.redis', MagicMock()):
                with patch('fastapi_limiter.depends.RateLimiter') as mock_limiter_dep:
                    async def mock_dependency_func(*args, **kwargs):
                        return None
                    mock_limiter_dep.return_value = mock_dependency_func
                    from main import app
                    return app


@pytest.fixture(scope="module")
async def async_client():
    app = create_test_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

@pytest.fixture
def valid_policy():
    return {
        "policy_id": f"policy_test_{uuid.uuid4().hex[:8]}",
        "conditions": [
            {"field": "source_ip", "operator": "==", "value": "1.1.1.1"},
            {"field": "destination_port", "operator": "==", "value": 80}
        ],
        "action": "block"
    }

@pytest.fixture
def valid_connection():
    return {
        "source_ip": "1.1.1.1",
        "destination_ip": "8.8.8.8",
        "destination_port": 80,
        "protocol": "TCP",
        "timestamp": "2025-01-01T00:00:00Z"
    }

@pytest.mark.anyio
async def test_debug_policy_structure(async_client):
    unique_policy_id = f"debug_policy_{uuid.uuid4().hex[:8]}"
    
    minimal = {
        "policy_id": unique_policy_id,
        "conditions": [],
        "action": "block"
    }
    
    response = await async_client.post("/policies", json=minimal)
    assert response.status_code == 201
    assert response.json()["policy_id"] == unique_policy_id
    assert response.json()["action"] == "block"

@pytest.mark.anyio
async def test_debug_connection_structure(async_client):
    minimal = {
        "source_ip": "1.1.1.1",
        "destination_ip": "8.8.8.8", 
        "destination_port": 80,
        "protocol": "TCP",
        "timestamp": "2025-01-01T00:00:00Z"
    }
    
    response = await async_client.post("/connections", json=minimal)
    assert response.status_code == 200
    data = response.json()
    assert "connection_id" in data
    assert "anomaly_score" in data
    assert data["decision"] in ["allow", "block", "alert", "drop"]

@pytest.mark.anyio
async def test_add_policy(async_client, valid_policy):
    response = await async_client.post("/policies", json=valid_policy)
    assert response.status_code == 201
    assert response.json()["policy_id"] == valid_policy["policy_id"]

@pytest.mark.anyio
async def test_add_duplicate_policy(async_client, valid_policy):
    await async_client.post("/policies", json=valid_policy)
    response = await async_client.post("/policies", json=valid_policy)
    assert response.status_code == 409

@pytest.mark.anyio
async def test_submit_connection(async_client, valid_connection):
    response = await async_client.post("/connections", json=valid_connection)
    assert response.status_code == 200
    data = response.json()
    assert "connection_id" in data
    assert data["decision"] in ["allow", "block", "alert", "drop"]
    assert data["source_ip"] == valid_connection["source_ip"]

@pytest.mark.anyio
async def test_get_existing_connection(async_client, valid_connection):
    post_response = await async_client.post("/connections", json=valid_connection)
    connection_id = post_response.json()["connection_id"]
    get_response = await async_client.get(f"/connections/{connection_id}")
    assert get_response.status_code == 200
    assert get_response.json()["connection_id"] == connection_id

@pytest.mark.anyio
async def test_get_nonexistent_connection(async_client):
    non_existing_id = str(uuid4())
    response = await async_client.get(f"/connections/{non_existing_id}")
    assert response.status_code == 404

@pytest.mark.anyio
@pytest.mark.parametrize("invalid_input", [
    {"destination_ip": "8.8.8.8", "destination_port": 80, "protocol": "TCP"},
    {"source_ip": "1.1.1.1", "destination_port": 80, "protocol": "TCP"},
    {"source_ip": "1.1.1.1", "destination_ip": "8.8.8.8", "protocol": "TCP"},
    {"source_ip": "1.1.1.1", "destination_ip": "8.8.8.8", "destination_port": 80},
    {"source_ip": "bad_ip", "destination_ip": "8.8.8.8", "destination_port": 80, "protocol": "TCP"},
])
async def test_invalid_connection_input(async_client, invalid_input):
    response = await async_client.post("/connections", json=invalid_input)
    assert response.status_code == 422


@pytest.mark.anyio
@pytest.mark.parametrize("invalid_operator", [
    {"policy_id": "invalid_op_1", "conditions": [{"field": "source_ip", "operator": "equals", "value": "1.1.1.1"}], "action": "block"},
    {"policy_id": "invalid_op_2", "conditions": [{"field": "source_ip", "operator": "!=", "value": "1.1.1.1"}], "action": "block"},
    {"policy_id": "invalid_op_3", "conditions": [{"field": "source_ip", "operator": "contains", "value": "1.1.1.1"}], "action": "block"}
])
async def test_add_policy_invalid_operator(async_client, invalid_operator):
    response = await async_client.post("/policies", json=invalid_operator)
    assert response.status_code == 422

@pytest.mark.anyio
@pytest.mark.parametrize("missing_field", [
    {"conditions": [{"field": "source_ip", "operator": "==", "value": "1.1.1.1"}], "action": "block"},
    {"policy_id": "missing_conditions", "action": "block"},
    {"policy_id": "missing_action", "conditions": [{"field": "source_ip", "operator": "==", "value": "1.1.1.1"}]},
    {"policy_id": "", "conditions": [{"field": "source_ip", "operator": "==", "value": "1.1.1.1"}], "action": "block"}
])
async def test_add_policy_missing_fields(async_client, missing_field):
    response = await async_client.post("/policies", json=missing_field)
    assert response.status_code == 422
