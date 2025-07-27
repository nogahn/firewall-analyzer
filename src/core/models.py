from datetime import datetime
from enum import Enum
import uuid
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator
from typing import Any, Optional, List, Literal
from fastapi.encoders import jsonable_encoder

class ConnectionField(str, Enum):
    SOURCE_IP = "source_ip"
    DESTINATION_IP = "destination_ip"
    DESTINATION_PORT = "destination_port"
    PROTOCOL = "protocol"


class PolicyCondition(BaseModel):
    field: ConnectionField
    operator: Literal["=="]
    value: Any

class Connection(BaseModel):
    connection_id: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    timestamp: datetime

    @classmethod
    def from_input(cls, data: "ConnectionInput") -> "Connection":
        clean_data = jsonable_encoder(data)
        return cls(
            connection_id=str(uuid.uuid4()),
            **clean_data
        )

class Policy(BaseModel):
    policy_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    conditions: List[PolicyCondition]
    action: Literal["allow", "block", "alert"]
    _original_order: Optional[int] = None

class AnalyzedConnection(Connection):
    anomaly_score: float
    decision: Literal["allow", "block", "alert", "drop"]
    policy_id: Optional[str] = None

class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"

class ConnectionInput(BaseModel):
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    destination_port: int = Field(..., ge=0, le=65535)
    protocol: Protocol
    timestamp: datetime

    @field_validator("protocol", mode="before")
    @classmethod
    def protocol_uppercase(cls, v):
        if isinstance(v, str):
            return v.upper()
        return v