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


class TimelineEventResponse(BaseModel):
    event_id: int
    created_at: datetime
    source: str
    event_type: str
    severity: SeverityLevel
    hostname: str | None
    container_name: str | None
    summary: str


class IncidentTimelineResponse(BaseModel):
    incident: IncidentResponse
    timeline: list[TimelineEventResponse]
    event_count: int


class IncidentEnrichmentResponse(BaseModel):
    incident: IncidentResponse
    event_count: int
    sources_seen: list[str]
    severities_seen: list[str]
    hosts_seen: list[str]
    containers_seen: list[str]
    event_types_seen: list[str]
    first_activity: datetime | None
    last_activity: datetime | None
    counts_by_source: dict[str, int]
    counts_by_severity: dict[str, int]
    counts_by_event_type: dict[str, int]