import pytest
from datetime import datetime, timedelta
import uuid
from unittest.mock import AsyncMock

from src.services.policy_manager import PolicyManager
from src.services.ai_service_client import AIServiceClient
from src.services.decision_engine import DecisionEngine
from src.core.models import Policy, Connection


@pytest.fixture
def policy_manager():
    return PolicyManager()


@pytest.fixture
def ai_client():
    client = AsyncMock(spec=AIServiceClient)
    return client


@pytest.fixture
def decision_engine(policy_manager, ai_client):
    return DecisionEngine(policy_manager, ai_client)


@pytest.fixture
def connection():
    return Connection(
        connection_id=str(uuid.uuid4()),
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        destination_port=80,
        protocol="TCP",
        timestamp=datetime.now(),
    )


@pytest.mark.asyncio
async def test_caching_connection_result(decision_engine, ai_client, connection):
    ai_client.get_anomaly_score.return_value = 0.5
    result1 = await decision_engine.evaluate_connection(connection)
    ai_client.get_anomaly_score.reset_mock()
    result2 = await decision_engine.evaluate_connection(connection)

    assert result1.anomaly_score == result2.anomaly_score
    assert result1.decision == result2.decision
    assert result1.policy_id == result2.policy_id
    ai_client.get_anomaly_score.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("anomaly_score, expected_decision", [
    (0.3, "drop"),
    (0.95, "alert"),
])
async def test_evaluate_connection_with_no_policy(
    decision_engine, ai_client, connection, anomaly_score, expected_decision
):
    ai_client.get_anomaly_score.return_value = anomaly_score
    result = await decision_engine.evaluate_connection(connection)

    assert result.anomaly_score == anomaly_score
    assert result.decision == expected_decision
    assert result.policy_id is None


@pytest.mark.asyncio
async def test_evaluate_connection_with_policy_match(
    decision_engine, ai_client, policy_manager, connection
):
    ai_client.get_anomaly_score.return_value = 0.1

    policy = Policy(
        policy_id="p1",
        conditions=[],
        action="allow"
    )
    policy_manager.add_policy(policy)

    result = await decision_engine.evaluate_connection(connection)

    assert result.decision == "allow"
    assert result.policy_id == "p1"


@pytest.mark.asyncio
async def test_connection_score_cached_but_decision_changes_with_policy(
    decision_engine, ai_client, policy_manager, connection
):
    ai_client.get_anomaly_score.return_value = 0.4
    result1 = await decision_engine.evaluate_connection(connection)

    policy = Policy(
        policy_id="p999",
        conditions=[],
        action="alert"
    )
    policy_manager.add_policy(policy)

    result2 = await decision_engine.evaluate_connection(connection)

    assert result1.anomaly_score == result2.anomaly_score
    assert result1.decision != result2.decision
    assert result2.policy_id == "p999"


@pytest.mark.asyncio
async def test_connection_with_different_timestamp_uses_cached_score(
    decision_engine, ai_client, connection
):
    ai_client.get_anomaly_score.return_value = 0.2
    result1 = await decision_engine.evaluate_connection(connection)

    new_conn = Connection(
        connection_id=str(uuid.uuid4()),
        source_ip=connection.source_ip,
        destination_ip=connection.destination_ip,
        destination_port=connection.destination_port,
        protocol=connection.protocol,
        timestamp=connection.timestamp + timedelta(seconds=30),
    )

    ai_client.get_anomaly_score.reset_mock()
    result2 = await decision_engine.evaluate_connection(new_conn)

    assert result2.anomaly_score == result1.anomaly_score
    ai_client.get_anomaly_score.assert_not_called()


def test_get_connection_returns_none_for_unknown_id(decision_engine):
    assert decision_engine.get_connection("nonexistent") is None


@pytest.mark.asyncio
async def test_get_connection_returns_analyzed_object(decision_engine, ai_client, connection):
    ai_client.get_anomaly_score.return_value = 0.7
    result = await decision_engine.evaluate_connection(connection)
    retrieved = decision_engine.get_connection(result.connection_id)

    assert retrieved is not None
    assert retrieved.connection_id == result.connection_id


@pytest.mark.asyncio
async def test_anomaly_override_non_blocking_policy(
    decision_engine, ai_client, policy_manager, connection
):
    """Test that high anomaly score overrides non-blocking/non-alerting policies"""
    ai_client.get_anomaly_score.return_value = 0.95

    policy = Policy(
        policy_id="p1",
        conditions=[],
        action="allow"
    )
    policy_manager.add_policy(policy)

    result = await decision_engine.evaluate_connection(connection)

    assert result.decision == "alert"
    assert result.policy_id == "p1"
    assert result.anomaly_score == 0.95


@pytest.mark.asyncio
async def test_anomaly_does_not_override_blocking_policy(
    decision_engine, ai_client, policy_manager, connection
):
    """Test that high anomaly score does NOT override blocking/alerting policies"""
    ai_client.get_anomaly_score.return_value = 0.95

    policy = Policy(
        policy_id="p2",
        conditions=[],
        action="block"
    )
    policy_manager.add_policy(policy)

    result = await decision_engine.evaluate_connection(connection)

    assert result.decision == "block"
    assert result.policy_id == "p2"
    assert result.anomaly_score == 0.95


@pytest.mark.asyncio
async def test_anomaly_does_not_override_alert_policy(
    decision_engine, ai_client, policy_manager, connection
):
    """Test that high anomaly score does NOT override alert policies"""
    ai_client.get_anomaly_score.return_value = 0.95

    policy = Policy(
        policy_id="p3",
        conditions=[], 
        action="alert"
    )
    policy_manager.add_policy(policy)

    result = await decision_engine.evaluate_connection(connection)

    assert result.decision == "alert"
    assert result.policy_id == "p3"
    assert result.anomaly_score == 0.95