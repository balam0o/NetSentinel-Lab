from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.schemas.events import EventIngest, EventResponse
from app.db.models import Event
from app.db.session import get_db
from app.services.correlator import correlate_event

router = APIRouter(prefix="/events", tags=["events"])

DbSession = Annotated[Session, Depends(get_db)]


@router.post(
    "/ingest",
    response_model=EventResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest_event(payload: EventIngest, db: DbSession):
    event = Event(
        source=payload.source,
        event_type=payload.event_type,
        severity=payload.severity,
        hostname=payload.hostname,
        container_name=payload.container_name,
        raw_event_json=payload.raw_event_json,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    correlate_event(db, event)

    return event


@router.get("", response_model=list[EventResponse])
def list_events(
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
):
    statement = select(Event).order_by(desc(Event.created_at)).limit(limit)
    events = db.execute(statement).scalars().all()
    return events


@router.get("/{event_id}", response_model=EventResponse)
def get_event(event_id: int, db: DbSession):
    event = db.get(Event, event_id)

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with id={event_id} was not found",
        )

    return event