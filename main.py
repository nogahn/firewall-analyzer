import uuid
from fastapi import FastAPI, Depends, HTTPException, status
from src.core.models import ConnectionInput, Policy, AnalyzedConnection, Connection
from src.services.policy_manager import PolicyManager
from src.services.ai_mock_service import AIMockService
from src.services.ai_service_client import AIServiceClient
from src.services.decision_engine import DecisionEngine
from config import Config
from contextlib import asynccontextmanager
import logging

from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from redis.asyncio import Redis as AiORedis

try:
    from fakeredis.aioredis import FakeRedis
except ImportError:
    try:
        from fakeredis import FakeAsyncRedis as FakeRedis
    except ImportError:
        FakeRedis = None

logging.basicConfig(
    level=Config.LOG_LEVEL,
    format=Config.LOG_FORMAT,
    datefmt=Config.LOG_DATE_FORMAT
)
logger = logging.getLogger(__name__)

ai_mock_service: AIMockService = AIMockService()
ai_service_client: AIServiceClient = AIServiceClient(ai_mock_service)
policy_manager: PolicyManager = PolicyManager()
decision_engine: DecisionEngine = DecisionEngine(policy_manager, ai_service_client)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Application startup: Starting AI service client...")
    await ai_service_client.start()
    if Config.REDIS_URL.startswith('redis://localhost') or Config.REDIS_URL == 'fake':
        if FakeRedis:
            redis_connection = FakeRedis(version=(7, 0, 0))
            logger.info("FastAPILimiter initialized with FakeRedis (in-memory) with Redis 7.0 compatibility.")
        else:
            logger.warning("FakeRedis not available, falling back to real Redis")
            redis_connection = AiORedis.from_url(Config.REDIS_URL, encoding="utf8", decode_responses=True)
    else:
        redis_connection = AiORedis.from_url(Config.REDIS_URL, encoding="utf8", decode_responses=True)
        logger.info(f"FastAPILimiter initialized with real Redis at {Config.REDIS_URL}.")

    try:
        await FastAPILimiter.init(redis_connection)
    except Exception as e:
        logger.error(f"Failed to initialize FastAPILimiter: {e}")
        logger.warning("Disabling rate limiting due to Redis initialization failure")
        app.dependency_overrides[RateLimiter] = lambda: None
    
    yield

    logger.info("Application shutdown: Stopping AI service client...")
    await ai_service_client.stop()

    if FastAPILimiter.redis:
        await FastAPILimiter.redis.close()

    logger.info("Application shutdown complete.")

app = FastAPI(
    title="AI-Driven Firewall Prototype",
    description="Backend prototype for an AI-driven firewall analyzing network connections and enforcing security policies.",
    version="0.1.0",
    lifespan=lifespan
)   

def get_decision_engine():
    return decision_engine

def get_policy_manager():
    return policy_manager

def get_rate_limiter():
    try:
        return RateLimiter(times=Config.API_RATE_LIMIT_TIMES, seconds=Config.API_RATE_LIMIT_SECONDS)
    except:
        return lambda: None

@app.post(
    "/connections",
    response_model=AnalyzedConnection,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_rate_limiter)],
)
async def submit_connection(
    connection_input: ConnectionInput,
    engine: DecisionEngine = Depends(get_decision_engine),
):
    try:
        connection = Connection.from_input(connection_input)
        analyzed_connection = await engine.evaluate_connection(connection)
        logger.info(
            f"Connection {analyzed_connection.connection_id} processed. "
            f"Source: {connection.source_ip}, Dest: {connection.destination_ip}:{connection.destination_port}, "
            f"Protocol: {connection.protocol}, Anomaly Score: {analyzed_connection.anomaly_score:.3f}, "
            f"Decision: {analyzed_connection.decision}, Policy ID: {analyzed_connection.policy_id or 'N/A'}"
        )
        return analyzed_connection
    except Exception as e:
        logger.error(
            f"Error processing connection {connection_input.source_ip}->{connection_input.destination_ip}:{connection_input.destination_port}: {e}",
            exc_info=True
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal server error: {e}")

@app.post("/policies", response_model=Policy, status_code=status.HTTP_201_CREATED)
async def define_security_policy(
    policy: Policy,
    manager: PolicyManager = Depends(get_policy_manager)
):
    try:
        manager.add_policy(policy)
        logger.info(f"Policy '{policy.policy_id}' defined successfully.")
        return policy
    except ValueError as e:
        logger.warning(f"Failed to add policy {policy.policy_id}: {e}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        logger.error(f"Error defining policy: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal server error: {e}")

@app.get("/connections/{connection_id}", response_model=AnalyzedConnection, status_code=status.HTTP_200_OK)
async def get_connection_details(
     connection_id: uuid.UUID,
    engine: DecisionEngine = Depends(get_decision_engine)
):
    connection_details = engine.get_connection(str(connection_id))
    if not connection_details:
        logger.warning(f"Connection ID {connection_id} not found.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    logger.info(f"Retrieved details for connection ID {connection_id}.")
    return connection_details