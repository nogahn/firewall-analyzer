import pytest
import asyncio
import time
from unittest.mock import MagicMock
from src.core.models import Connection
from src.services.ai_mock_service import AIMockService
from src.services.ai_service_client import AIServiceClient
from config import Config

@pytest.fixture(autouse=True)
def mock_config(monkeypatch):
    monkeypatch.setattr(Config, 'AI_MAX_BATCH_SIZE', 10)
    monkeypatch.setattr(Config, 'AI_BATCH_TIMEOUT_MS', 100)
    monkeypatch.setattr(Config, 'AI_RATE_LIMIT_RPS', 50)
    monkeypatch.setattr(Config, 'AI_MOCK_PROCESSING_TIME_MS', 10)
    monkeypatch.setattr(Config, 'AI_MOCK_ERROR_RATE', 0.0)

@pytest.fixture
def mock_ai_service():
    mock = MagicMock(spec=AIMockService)
    mock.analyze_connections.side_effect = lambda conns: [0.5] * len(conns)
    return mock

def create_connection(conn_id: str):
    return Connection(
        connection_id=conn_id,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        destination_port=80,
        protocol="TCP",
        timestamp=time.time()
    )

@pytest.mark.asyncio
async def test_get_anomaly_score_starts_client(mock_ai_service):
    client = AIServiceClient(mock_ai_service)
    conn = create_connection("test")
    score = await client.get_anomaly_score(conn)
    assert 0 <= score <= 1
    mock_ai_service.analyze_connections.assert_called_once()
    await client.stop()

@pytest.mark.asyncio
async def test_shutdown_cancels_pending(mock_ai_service):
    def slow_analyze(conns):
        time.sleep(2.0)  
        return [0.5] * len(conns)
    
    mock_ai_service.analyze_connections.side_effect = slow_analyze

    client = AIServiceClient(mock_ai_service)
    await client.start()
    conn = create_connection("test-timeout")
    fut = asyncio.create_task(client.get_anomaly_score(conn))
    await asyncio.sleep(0.05)

    await client.stop()
    assert fut.done()
    
    if fut.cancelled():
        with pytest.raises(asyncio.CancelledError):
            await fut
    else:
        result = await fut
        assert isinstance(result, float)

@pytest.mark.asyncio
async def test_graceful_shutdown_processes_all(mock_ai_service):
    client = AIServiceClient(mock_ai_service)
    await client.start()
    conns = [create_connection(f"conn-{i}") for i in range(3)]
    futures = [asyncio.create_task(client.get_anomaly_score(c)) for c in conns]
    await asyncio.sleep(0.01)
    await client.stop()
    for f in futures:
        assert f.done()
        assert not f.cancelled()
        score = await f
        assert 0 <= score <= 1
    mock_ai_service.analyze_connections.assert_called_once()

@pytest.mark.asyncio
async def test_error_handling():
    class FailAI(AIMockService):
        def analyze_connections(self, conns):
            raise Exception("Simulated failure")
    client = AIServiceClient(FailAI())
    await client.start()
    conn = create_connection("fail-1")
    fut = asyncio.create_task(client.get_anomaly_score(conn))
    await asyncio.sleep(0.01)
    with pytest.raises(Exception, match="Simulated failure"):
        await fut
    await client.stop()

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rate_limit,batch_size,batch_timeout",
    [
        (2, 1, 1),
        (100, 10, 10)
    ]
)
async def test_rate_limiting_and_batching(mock_ai_service, monkeypatch, rate_limit, batch_size, batch_timeout):
    monkeypatch.setattr(Config, 'AI_RATE_LIMIT_RPS', rate_limit)
    monkeypatch.setattr(Config, 'AI_MAX_BATCH_SIZE', batch_size)
    monkeypatch.setattr(Config, 'AI_BATCH_TIMEOUT_MS', batch_timeout)
    client = AIServiceClient(mock_ai_service)
    client.rate_limit_rps = Config.AI_RATE_LIMIT_RPS
    client.min_interval = 1.0 / client.rate_limit_rps
    client.max_batch_size = Config.AI_MAX_BATCH_SIZE
    client.batch_timeout = Config.AI_BATCH_TIMEOUT_MS / 1000.0
    await client.start()

    if batch_size == 1:
        conns = [create_connection(f"conn-{i}") for i in range(3)]
        start = time.time()
        futures = [asyncio.create_task(client.get_anomaly_score(c)) for c in conns]
        results = await asyncio.gather(*futures)
        duration = time.time() - start
        assert duration >= 1.0
        assert all(0 <= r <= 1 for r in results)
        assert mock_ai_service.analyze_connections.call_count == 3
    else:
        conns = [create_connection(f"conn-{i}") for i in range(batch_size)]
        futures = [asyncio.create_task(client.get_anomaly_score(c)) for c in conns]
        scores = await asyncio.gather(*futures)
        assert all(0 <= s <= 1 for s in scores)
        mock_ai_service.analyze_connections.assert_called_once()
    await client.stop()

@pytest.mark.asyncio
async def test_start_and_stop_idempotent(mock_ai_service):
    client = AIServiceClient(mock_ai_service)
    await client.start()
    await client.start()
    await client.stop()
    await client.stop()

@pytest.mark.asyncio
async def test_estimated_throughput(mock_ai_service, monkeypatch):
    num_connections = 1000
    expected_min_duration = 1.0
    monkeypatch.setattr(Config, 'AI_MAX_BATCH_SIZE', 10)
    monkeypatch.setattr(Config, 'AI_BATCH_TIMEOUT_MS', 10)
    monkeypatch.setattr(Config, 'AI_RATE_LIMIT_RPS', 100)
    monkeypatch.setattr(Config, 'AI_MOCK_PROCESSING_TIME_MS', 10)

    client = AIServiceClient(mock_ai_service)
    client.max_batch_size = Config.AI_MAX_BATCH_SIZE
    client.batch_timeout = Config.AI_BATCH_TIMEOUT_MS / 1000.0
    client.rate_limit_rps = Config.AI_RATE_LIMIT_RPS
    client.min_interval = 1.0 / client.rate_limit_rps

    await client.start()
    mock_ai_service.analyze_connections.reset_mock()

    connections = [create_connection(f"perf-{i}") for i in range(num_connections)]
    start_time = time.time()
    tasks = [asyncio.create_task(client.get_anomaly_score(c)) for c in connections]
    results = await asyncio.gather(*tasks)
    duration = time.time() - start_time

    assert len(results) == num_connections
    assert all(isinstance(r, float) for r in results)
    assert client.pending_queue.empty()
    assert mock_ai_service.analyze_connections.call_count == num_connections / Config.AI_MAX_BATCH_SIZE
    
    assert duration >= expected_min_duration
    await client.stop()