from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


SeverityLevel = Literal["low", "medium", "high", "critical"]


class EventIngest(BaseModel):
    source: str = Field(min_length=1, max_length=50)
    event_type: str = Field(min_length=1, max_length=100)
    severity: SeverityLevel = "low"
    hostname: str | None = Field(default=None, max_length=255)
    container_name: str | None = Field(default=None, max_length=255)
    raw_event_json: dict[str, Any] = Field(default_factory=dict)


class EventResponse(BaseModel):
    id: int
    source: str
    event_type: str
    severity: str
    hostname: str | None
    container_name: str | None
    raw_event_json: dict[str, Any]
    created_at: datetime

    model_config = {
        "from_attributes": True,
    }