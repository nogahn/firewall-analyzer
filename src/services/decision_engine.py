import hashlib
from typing import Optional

from src.core.models import AnalyzedConnection, Connection
from src.services.policy_manager import PolicyManager
from src.services.ai_service_client import AIServiceClient


class DecisionEngine:
    def __init__(self, policy_manager: PolicyManager, ai_client: AIServiceClient):
        self.policy_manager = policy_manager
        self.ai_client = ai_client
        self._connection_by_id: dict[str, AnalyzedConnection] = {}
        self._cache_key_to_anomaly_score: dict[str, float] = {}

    def _make_cache_key(self, conn: Connection) -> str:
        key_str = f"{conn.source_ip}-{conn.destination_ip}-{conn.destination_port}-{conn.protocol}"
        return hashlib.sha256(key_str.encode()).hexdigest()

    async def evaluate_connection(self, conn: Connection) -> AnalyzedConnection:
        cache_key = self._make_cache_key(conn)

        if cache_key in self._cache_key_to_anomaly_score:
            anomaly_score = self._cache_key_to_anomaly_score[cache_key]
        else:
            anomaly_score = await self.ai_client.get_anomaly_score(conn)
            self._cache_key_to_anomaly_score[cache_key] = anomaly_score

        matched_policy = self.policy_manager.get_matching_policy(conn)


        if matched_policy:
            decision = matched_policy.action
            policy_id = matched_policy.policy_id
            
            if anomaly_score > 0.8 and matched_policy.action not in ["block", "alert"]:
                decision = "alert"
                
        elif anomaly_score > 0.8:
            decision = "alert"
            policy_id = None
        else:
            decision = "drop"
            policy_id = None

        analyzed = AnalyzedConnection(
            **conn.model_dump(),
            anomaly_score=anomaly_score,
            decision=decision,
            policy_id=policy_id,
        )

        self._connection_by_id[conn.connection_id] = analyzed
        return analyzed

    def get_connection(self, connection_id: str) -> Optional[AnalyzedConnection]:
        return self._connection_by_id.get(connection_id)
