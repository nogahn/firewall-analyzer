import pytest
import time
from src.services.ai_mock_service import AIMockService
from src.core.models import Connection
from config import Config

@pytest.fixture(autouse=True)
def no_sleep_mock(monkeypatch):
    """Mocks time.sleep for faster tests."""
    def mock_sleep(seconds):
        pass
    monkeypatch.setattr(time, "sleep", mock_sleep)

@pytest.fixture(autouse=True)
def mock_config_for_mock_service(monkeypatch):
    """Mocks Config values for AIMockService initialization."""
    monkeypatch.setattr(Config, 'AI_MOCK_PROCESSING_TIME_MS', 10)
    monkeypatch.setattr(Config, 'AI_MOCK_ERROR_RATE', 0.05)

def test_aimockservice_initialization():
    """Tests AIMockService initialization."""
    service = AIMockService()
    assert service.processing_time_ms == Config.AI_MOCK_PROCESSING_TIME_MS
    assert service.error_rate == Config.AI_MOCK_ERROR_RATE

def test_aimockservice_analyze_connections_basic():
    """Tests basic connection analysis."""
    service = AIMockService()
    connections = [
        Connection(connection_id=f"conn-{i}", source_ip="1.1.1.1", destination_ip="2.2.2.2", port=80, protocol="TCP", timestamp=time.time(), destination_port=443) 
        for i in range(5)
    ]

    scores = service.analyze_connections(connections)
    assert len(scores) == 5
    assert all(0.0 <= score <= 1.0 for score in scores)

def test_aimockservice_analyze_connections_empty():
    """Tests connection analysis with an empty list."""
    service = AIMockService()
    scores = service.analyze_connections([])
    assert scores == []

def test_aimockservice_simulated_error(monkeypatch):
    """Tests simulated error in the service."""
    service = AIMockService()
    connections = [Connection(connection_id="conn-1", source_ip="1.1.1.1", destination_ip="2.2.2.2", port=80, protocol="TCP", timestamp=time.time(), destination_port=443)]
    monkeypatch.setattr('random.random', lambda: 0.01)
    with pytest.raises(Exception, match="Mock AI Service Error"):
        service.analyze_connections(connections)

