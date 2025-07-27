import logging

class Config:
    # API Rate Limiting settings
    API_RATE_LIMIT_TIMES = 1000
    API_RATE_LIMIT_SECONDS = 1

    # AI Service settings
    AI_MOCK_PROCESSING_TIME_MS = 10
    AI_MOCK_ERROR_RATE = 0.05
    AI_MAX_BATCH_SIZE = 10
    AI_BATCH_TIMEOUT_MS = 50
    AI_RATE_LIMIT_RPS = 10.0 # 10 batches/sec * 10 conn/batch = 100 conn/sec

    # Redis settings
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379
    REDIS_DB = 0
    REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

    # Logging settings
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'