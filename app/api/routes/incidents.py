from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import asc, desc, select
from sqlalchemy.orm import Session

from app.api.schemas.events import EventResponse, SeverityLevel
from app.api.schemas.incidents import (
    IncidentDetailResponse,
    IncidentResponse,
    IncidentStatus,
    IncidentTimelineResponse,
    IncidentUpdate,
    TimelineEventResponse,
)
from app.db.models import Event, Incident, IncidentEvent
from app.db.session import get_db

router = APIRouter(prefix="/incidents", tags=["incidents"])

DbSession = Annotated[Session, Depends(get_db)]

IncidentSortField = Literal["last_seen", "first_seen", "title", "status", "severity"]
SortOrder = Literal["asc", "desc"]


def build_timeline_summary(event: Event) -> str:
    raw = event.raw_event_json or {}

    for key in ("rule", "output", "message"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return event.event_type.replace("_", " ")


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    severity: SeverityLevel | None = None,
    title_contains: str | None = None,
    sort_by: IncidentSortField = "last_seen",
    sort_order: SortOrder = "desc",
):
    statement = select(Incident)

    if status_filter is not None:
        statement = statement.where(Incident.status == status_filter)

    if severity is not None:
        statement = statement.where(Incident.severity == severity)

    if title_contains is not None:
        statement = statement.where(Incident.title.ilike(f"%{title_contains}%"))

    sort_column_map = {
        "last_seen": Incident.last_seen,
        "first_seen": Incident.first_seen,
        "title": Incident.title,
        "status": Incident.status,
        "severity": Incident.severity,
    }

    sort_column = sort_column_map[sort_by]
    order_clause = asc(sort_column) if sort_order == "asc" else desc(sort_column)

    statement = statement.order_by(order_clause).offset(offset).limit(limit)

    incidents = db.execute(statement).scalars().all()
    return incidents


@router.get("/{incident_id}/detail", response_model=IncidentDetailResponse)
def get_incident_detail(
    incident_id: int,
    db: DbSession,
    limit: int = Query(default=100, ge=1, le=500),
):
    incident = db.get(Incident, incident_id)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id={incident_id} was not found",
        )

    statement = (
        select(Event)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(desc(Event.created_at), desc(Event.id))
        .limit(limit)
    )

    events = db.execute(statement).scalars().all()

    return IncidentDetailResponse(
        incident=incident,
        events=events,
        event_count=len(events),
    )


@router.get("/{incident_id}/timeline", response_model=IncidentTimelineResponse)
def get_incident_timeline(
    incident_id: int,
    db: DbSession,
    limit: int = Query(default=100, ge=1, le=500),
):
    incident = db.get(Incident, incident_id)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id={incident_id} was not found",
        )

    statement = (
        select(Event)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(asc(Event.created_at), asc(Event.id))
        .limit(limit)
    )

    events = db.execute(statement).scalars().all()

    timeline = [
        TimelineEventResponse(
            event_id=event.id,
            created_at=event.created_at,
            source=event.source,
            event_type=event.event_type,
            severity=event.severity,
            hostname=event.hostname,
            container_name=event.container_name,
            summary=build_timeline_summary(event),
        )
        for event in events
    ]

    return IncidentTimelineResponse(
        incident=incident,
        timeline=timeline,
        event_count=len(timeline),
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: DbSession):
    incident = db.get(Incident, incident_id)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id={incident_id} was not found",
        )

    return incident


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: int, payload: IncidentUpdate, db: DbSession):
    incident = db.get(Incident, incident_id)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id={incident_id} was not found",
        )

    incident.status = payload.status
    db.commit()
    db.refresh(incident)

    return incident


@router.get("/{incident_id}/events", response_model=list[EventResponse])
def get_incident_events(
    incident_id: int,
    db: DbSession,
    limit: int = Query(default=100, ge=1, le=500),
):
    incident = db.get(Incident, incident_id)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id={incident_id} was not found",
        )

    statement = (
        select(Event)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(desc(Event.created_at), desc(Event.id))
        .limit(limit)
    )

    events = db.execute(statement).scalars().all()
    return events