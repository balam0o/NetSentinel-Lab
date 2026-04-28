import re
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import asc, desc, select
from sqlalchemy.orm import Session

from app.api.schemas.events import EventIngest, EventResponse, SeverityLevel
from app.api.schemas.falco import FalcoEventIngest
from app.db.models import Event
from app.db.session import get_db
from app.services.correlator import correlate_event

router = APIRouter(prefix="/events", tags=["events"])

DbSession = Annotated[Session, Depends(get_db)]

EventSortField = Literal["created_at", "source", "event_type", "hostname", "container_name"]
SortOrder = Literal["asc", "desc"]


def persist_event(db: Session, event: Event) -> Event:
    db.add(event)
    db.commit()
    db.refresh(event)

    correlate_event(db, event)

    return event


def normalize_falco_rule(rule: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", rule.strip().lower())
    normalized = normalized.strip("_")
    return normalized or "falco_event"


def map_falco_priority_to_severity(priority: str) -> SeverityLevel:
    value = priority.strip().lower()

    if value in {"emergency", "alert", "critical"}:
        return "critical"
    if value == "error":
        return "high"
    if value in {"warning", "notice"}:
        return "medium"

    return "low"


def first_non_empty_string(values: list[Any]) -> str | None:
    for value in values:
        if value is None:
            continue

        text = str(value).strip()
        if text:
            return text

    return None


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

    return persist_event(db, event)


@router.post(
    "/ingest/falco",
    response_model=EventResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest_falco_event(payload: FalcoEventIngest, db: DbSession):
    output_fields = payload.output_fields

    event = Event(
        source="falco",
        event_type=normalize_falco_rule(payload.rule),
        severity=map_falco_priority_to_severity(payload.priority),
        hostname=first_non_empty_string(
            [
                output_fields.get("evt.hostname"),
                output_fields.get("hostname"),
                output_fields.get("k8s.node.name"),
            ]
        ),
        container_name=first_non_empty_string(
            [
                output_fields.get("container.name"),
                output_fields.get("k8s.pod.name"),
                output_fields.get("container.id"),
            ]
        ),
        raw_event_json={
            "output": payload.output,
            "priority": payload.priority,
            "rule": payload.rule,
            "output_fields": output_fields,
        },
    )

    return persist_event(db, event)


@router.get("", response_model=list[EventResponse])
def list_events(
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: SeverityLevel | None = None,
    source: str | None = None,
    event_type: str | None = None,
    hostname: str | None = None,
    container_name: str | None = None,
    sort_by: EventSortField = "created_at",
    sort_order: SortOrder = "desc",
):
    statement = select(Event)

    if severity is not None:
        statement = statement.where(Event.severity == severity)

    if source is not None:
        statement = statement.where(Event.source == source)

    if event_type is not None:
        statement = statement.where(Event.event_type == event_type)

    if hostname is not None:
        statement = statement.where(Event.hostname == hostname)

    if container_name is not None:
        statement = statement.where(Event.container_name == container_name)

    sort_column_map = {
        "created_at": Event.created_at,
        "source": Event.source,
        "event_type": Event.event_type,
        "hostname": Event.hostname,
        "container_name": Event.container_name,
    }

    sort_column = sort_column_map[sort_by]
    order_clause = asc(sort_column) if sort_order == "asc" else desc(sort_column)

    statement = statement.order_by(order_clause).offset(offset).limit(limit)

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