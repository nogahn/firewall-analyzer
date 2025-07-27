from typing import Optional, List, Dict, Any, Set
import logging

from src.core.models import Policy, Connection

logger = logging.getLogger(__name__)

class PolicyManager:
    def __init__(self):
        """Initializes the Policy Manager."""
        self._policies: List[Policy] = []
        self._policy_id_map: Dict[str, Policy] = {}
        self._next_order = 0
        self._policies_without_conditions: Set[int] = set()

        self._indexes: Dict[str, Dict[Any, Set]] = {
            "destination_port": {},
            "source_ip": {},
            "destination_ip": {},
            "protocol": {}
        }
        logger.info("PolicyManager initialized.")

    def add_policy(self, policy: Policy):
        """Adds a policy to the manager, assigns an original order if not set, and updates indexes."""
        if policy.policy_id in self._policy_id_map:
            logger.error(f"Policy '{policy.policy_id}' already exists")
            raise ValueError(f"Policy ID {policy.policy_id} already exists.")
        policy._original_order = self._next_order
        self._next_order += 1
        self._policies.append(policy)
        self._policy_id_map[policy.policy_id] = policy
        if not policy.conditions:
            self._policies_without_conditions.add(policy._original_order)
        self._update_indexes(policy)
        logger.info(f"Policy '{policy.policy_id}' added/updated. Order: {policy._original_order}")

    def _update_indexes(self, policy: Policy):
        """Internal method to add a policy's conditions to the indexes."""
        for condition in policy.conditions:
            field = condition.field
            value = condition.value
            if field in self._indexes:
                if value not in self._indexes[field]:
                    self._indexes[field][value] = set()
                self._indexes[field][value].add(policy._original_order)
                logger.debug(f"Indexed policy '{policy.policy_id}' by {field}={value}")

    def get_matching_policy(self, connection: Connection) -> Optional[Policy]:
        """
        Finds the first matching policy for a given connection based on order.
        Uses set intersection for efficient filtering.
        """
        candidate_sets: List[Set[int]] = []

        if self._policies_without_conditions:
            candidate_sets.append(self._policies_without_conditions)

        for field in self._indexes:
            value = getattr(connection, field, None)
            if value is not None:
                matches = self._indexes[field].get(value)
                if matches:
                    candidate_sets.append(matches)

        if candidate_sets:
            common_orders = set.union(*candidate_sets)
            for order in sorted(common_orders):
                policy = self._policies[order]
                if self._evaluate_policy_conditions(policy, connection):
                    return policy

        return None
    
    def _evaluate_policy_conditions(self, policy: Policy, connection: Connection) -> bool:
        for condition in policy.conditions:
            connection_value = getattr(connection, condition.field.value)
            if connection_value != condition.value:
                return False
        return True

    def clear_policies(self):
        """Clears all policies and resets the manager."""
        self._policies = []
        self._policy_id_map = {}
        self._indexes = {
            "destination_port": {},
            "source_ip": {},
            "destination_ip": {},
            "protocol": {}
        }
        self._next_order = 0
        logger.info("All policies cleared from PolicyManager.")
