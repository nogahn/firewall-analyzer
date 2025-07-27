import time
import random
import logging
from typing import List
from src.core.models import Connection
from config import Config

logger = logging.getLogger(__name__)

class AIMockService:
    def __init__(self):
        """
        Initializes the mock AI service using parameters from Config.
        """
        self.processing_time_ms = Config.AI_MOCK_PROCESSING_TIME_MS
        self.error_rate = Config.AI_MOCK_ERROR_RATE
        logger.info(f"AIMockService initialized (proc_time={self.processing_time_ms}ms, error_rate={self.error_rate}).")

    def analyze_connections(self, connections: List[Connection]) -> List[float]:
        """Simulates sending a batch of connections to the AI for analysis."""
        if not connections:
            logger.debug("AIMockService: Received empty batch.")
            return []

        batch_size = len(connections)
        logger.debug(f"AIMockService: Simulating {self.processing_time_ms}ms delay for batch of {batch_size} connections.")
        time.sleep(self.processing_time_ms / 1000.0)

        if random.random() < self.error_rate:
            logger.error(f"AIMockService: Simulated error for batch of {batch_size}.")
            raise Exception("Mock AI Service Error: Simulated API unavailability or processing failure.")

        scores = []
        for _ in connections:
            score = random.uniform(0.0, 1.0)
            scores.append(round(score, 3))
        
        return scores