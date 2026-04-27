from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.schemas.events import EventResponse, SeverityLevel
from app.api.schemas.incidents import IncidentResponse, IncidentStatus, IncidentUpdate
from app.db.models import Event, Incident, IncidentEvent
from app.db.session import get_db

router = APIRouter(prefix="/incidents", tags=["incidents"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    severity: SeverityLevel | None = None,
    title_contains: str | None = None,
):
    statement = select(Incident)

    if status_filter is not None:
        statement = statement.where(Incident.status == status_filter)

    if severity is not None:
        statement = statement.where(Incident.severity == severity)

    if title_contains is not None:
        statement = statement.where(Incident.title.ilike(f"%{title_contains}%"))

    statement = statement.order_by(desc(Incident.last_seen)).limit(limit)

    incidents = db.execute(statement).scalars().all()
    return incidents


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
        .order_by(desc(Event.created_at))
        .limit(limit)
    )

    events = db.execute(statement).scalars().all()
    return events