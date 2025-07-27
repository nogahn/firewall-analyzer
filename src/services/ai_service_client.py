import asyncio
import time
import logging
from typing import List, Tuple
from asyncio import Queue, Event, Future
from src.core.models import Connection
from src.services.ai_mock_service import AIMockService
from config import Config

logger = logging.getLogger(__name__)

class AIServiceClient:
    """Manages communication with the AI anomaly detection service, implementing batching and rate limiting."""

    def __init__(self, ai_mock_service: AIMockService):
        """Initializes the AI Service Client using parameters from Config."""
        self.ai_service = ai_mock_service
        self.max_batch_size = Config.AI_MAX_BATCH_SIZE
        self.batch_timeout = Config.AI_BATCH_TIMEOUT_MS / 1000.0
        self.rate_limit_rps = Config.AI_RATE_LIMIT_RPS
        self.min_interval = 1.0 / self.rate_limit_rps if self.rate_limit_rps > 0 else 0

        self.pending_queue: Queue[Tuple[Connection, Future]] = Queue()
        self.last_request_time = 0.0
        self.processing_task: asyncio.Task | None = None
        self.shutdown_event = Event()

        logger.info(f"AIServiceClient initialized: max_batch_size={self.max_batch_size}, batch_timeout_ms={Config.AI_BATCH_TIMEOUT_MS}, rate_limit_rps={self.rate_limit_rps}.")

    async def _collect_batch(self) -> Tuple[List[Connection], List[Future]]:
        """Collect a batch of connections, respecting size and timeout limits."""
        connections = []
        futures = []
        batch_start_time = time.time()
        
        while len(connections) < self.max_batch_size:
            elapsed = time.time() - batch_start_time
            timeout_remaining = max(0.001, self.batch_timeout - elapsed)
            
            try:
                connection, future = await asyncio.wait_for(
                    self.pending_queue.get(),
                    timeout=timeout_remaining
                )
                connections.append(connection)
                futures.append(future)
                self.pending_queue.task_done()
                
                if len(connections) == 1:
                    batch_start_time = time.time()
                    
            except asyncio.TimeoutError:
                break
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"AIServiceClient: Error collecting batch: {e}")
                break
        
        return connections, futures

    async def _send_batch_to_ai(self, connections: List[Connection], futures: List[Future]):
        """Sends the collected batch to the AI service, applying rate limiting."""
        if not connections:
            return
            
        now = time.time()
        time_since_last_request = now - self.last_request_time
        if time_since_last_request < self.min_interval:
            wait_time = self.min_interval - time_since_last_request
            logger.debug(f"AIServiceClient: Rate limit hit. Waiting for {wait_time:.3f}s.")
            await asyncio.sleep(wait_time)
        
        self.last_request_time = time.time()
        batch_size = len(connections)
        logger.info(f"AIServiceClient: Sending batch of {batch_size} connections to AI service.")
        
        try:
            scores = self.ai_service.analyze_connections(connections)
            for i, score in enumerate(scores):
                if i < len(futures) and not futures[i].done():
                    futures[i].set_result(score)
        except Exception as e:
            logger.error(f"AIServiceClient: Error processing AI batch: {e}")
            for future in futures:
                if not future.done():
                    future.set_exception(e)

    async def _handle_shutdown(self):
        """Handles graceful shutdown, processing any remaining items."""
        logger.info("AIServiceClient: Processing remaining items during shutdown.")
        
        while not self.pending_queue.empty():
            connections = []
            futures = []
            try:
                while not self.pending_queue.empty() and len(connections) < self.max_batch_size:
                    connection, future = self.pending_queue.get_nowait()
                    connections.append(connection)
                    futures.append(future)
                    self.pending_queue.task_done()
            except asyncio.QueueEmpty:
                break
            
            if connections:
                logger.info(f"AIServiceClient: Sending final batch of {len(connections)} connections during shutdown.")
                await self._send_batch_to_ai(connections, futures)
        try:
            while not self.pending_queue.empty():
                _, future = self.pending_queue.get_nowait()
                if not future.done():
                    future.set_exception(asyncio.CancelledError("AI service client is shutting down."))
                self.pending_queue.task_done()
        except asyncio.QueueEmpty:
            pass
        
        logger.info("AIServiceClient: Shutdown processing completed.")

    async def _process_batches(self):
        """Continuously processes batches from the pending queue, handling batching and rate limiting."""
        logger.info("AIServiceClient: Started batch processing loop.")
        
        try:
            while not self.shutdown_event.is_set():
                try:
                    connections, futures = await self._collect_batch() 
                    if connections:
                        await self._send_batch_to_ai(connections, futures)
                    elif self.shutdown_event.is_set():
                        break
                    else:
                        await asyncio.sleep(0.001)  
                except asyncio.CancelledError:
                    logger.info("AIServiceClient: Batch processing cancelled.")
                    break
                except Exception as e:
                    logger.error(f"AIServiceClient: Unexpected error in batch processing: {e}")
                    await asyncio.sleep(0.001)
                    
        finally:
            await self._handle_shutdown()
            logger.info("AIServiceClient: Batch processing loop ended.")

    async def get_anomaly_score(self, connection: Connection) -> float:
        """Submits a single connection for AI anomaly scoring, batched and rate-limited internally."""
        if self.processing_task is None or self.processing_task.done():
            logger.warning("AIServiceClient: get_anomaly_score called before client was started or after it stopped. Starting now.")
            await self.start()

        future = Future()
        await self.pending_queue.put((connection, future))
        logger.debug(f"AIServiceClient: Connection {connection.connection_id} added to queue.")
        return await future

    async def start(self):
        """Starts the background processing task for AI batches."""
        if self.processing_task is None or self.processing_task.done():
            self.shutdown_event.clear()
            self.processing_task = asyncio.create_task(self._process_batches())
            logger.info("AIServiceClient: Background processing task started.")
        else:
            logger.info("AIServiceClient: Background processing task is already running.")

    async def stop(self):
        """Stops the background processing task and waits for pending requests to complete."""
        if self.processing_task and not self.processing_task.done():
            logger.info("AIServiceClient: Initiating graceful shutdown.")
            self.shutdown_event.set()
            
            try:
                await asyncio.wait_for(self.processing_task, timeout=10.0)
                logger.info("AIServiceClient: Background processing task completed during stop.")
            except asyncio.TimeoutError:
                logger.warning("AIServiceClient: Background processing task did not stop gracefully within timeout. Cancelling.")
                self.processing_task.cancel()
                try:
                    await self.processing_task
                except asyncio.CancelledError:
                    pass
            except Exception as e:
                logger.error(f"AIServiceClient: Error while stopping background task: {e}")
            finally:
                self.processing_task = None
                logger.info("AIServiceClient: Client stopped.")
        else:
            logger.info("AIServiceClient: Client was not running or already stopped.")

        if not self.pending_queue.empty():
            await self.pending_queue.join()