from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.api.schemas.events import EventResponse


IncidentStatus = Literal["open", "closed"]
SeverityLevel = Literal["low", "medium", "high", "critical"]


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str | None
    severity: SeverityLevel
    status: IncidentStatus
    first_seen: datetime
    last_seen: datetime

    model_config = {
        "from_attributes": True,
    }


class IncidentUpdate(BaseModel):
    status: IncidentStatus


class IncidentDetailResponse(BaseModel):
    incident: IncidentResponse
    events: list[EventResponse]
    event_count: int