from collections import Counter
from typing import Annotated, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import asc, desc, select
from sqlalchemy.orm import Session
from app.api.schemas.events import EventResponse, SeverityLevel
from app.api.schemas.incidents import (
    IncidentDetailResponse,
    IncidentEnrichmentResponse,
    IncidentResponse,
    IncidentStatus,
    IncidentTimelineResponse,
    IncidentUpdate,
    TimelineEventResponse,
)
from app.db.models import Event, Incident, IncidentEvent
from app.db.session import get_db
from fastapi import APIRouter, Depends
from app.core.auth import require_api_key
from fastapi import APIRouter, Security
from app.core.auth import require_api_key
import csv
from io import StringIO
from fastapi.responses import Response
import json
from datetime import datetime, timezone

router = APIRouter(
    prefix="/incidents",
    tags=["incidents"],
    dependencies=[Security(require_api_key)],
)

DbSession = Annotated[Session, Depends(get_db)]

IncidentSortField = Literal["last_seen", "first_seen", "title", "status", "severity"]
SortOrder = Literal["asc", "desc"]


def export_datetime(value):
    return value.isoformat() if value else None


def build_export_event_summary(event: Event) -> str:
    raw = event.raw_event_json or {}

    if isinstance(raw, dict):
        return (
            raw.get("rule")
            or raw.get("signature")
            or raw.get("message")
            or raw.get("output")
            or event.event_type
        )

    return event.event_type

def build_timeline_summary(event: Event) -> str:
    raw = event.raw_event_json or {}

    for key in ("rule", "output", "message"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return event.event_type.replace("_", " ")


def get_incident_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id={incident_id} was not found",
        )

    return incident


def get_incident_linked_events(
    db: Session,
    incident_id: int,
    limit: int,
    newest_first: bool,
) -> list[Event]:
    order_clauses = (
        [desc(Event.created_at), desc(Event.id)]
        if newest_first
        else [asc(Event.created_at), asc(Event.id)]
    )

    statement = (
        select(Event)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(*order_clauses)
        .limit(limit)
    )

    return db.execute(statement).scalars().all()


@router.get("/{incident_id}/export/json", response_class=Response)
def export_incident_json(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    statement = (
        select(Event)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(Event.created_at.asc(), Event.id.asc())
    )

    events = db.execute(statement).scalars().all()

    counts_by_source = {}
    counts_by_severity = {}
    counts_by_event_type = {}

    sources_seen = set()
    hosts_seen = set()
    containers_seen = set()
    event_types_seen = set()

    timeline = []

    for event in events:
        counts_by_source[event.source] = counts_by_source.get(event.source, 0) + 1
        counts_by_severity[event.severity] = counts_by_severity.get(event.severity, 0) + 1
        counts_by_event_type[event.event_type] = counts_by_event_type.get(event.event_type, 0) + 1

        if event.source:
            sources_seen.add(event.source)
        if event.hostname:
            hosts_seen.add(event.hostname)
        if event.container_name:
            containers_seen.add(event.container_name)
        if event.event_type:
            event_types_seen.add(event.event_type)

        timeline.append(
            {
                "event_id": event.id,
                "event_type": event.event_type,
                "source": event.source,
                "severity": event.severity,
                "created_at": export_datetime(event.created_at),
                "summary": build_export_event_summary(event),
            }
        )

    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "correlation_key": incident.correlation_key,
            "first_seen": export_datetime(incident.first_seen),
            "last_seen": export_datetime(incident.last_seen),
        },
        "event_count": len(events),
        "events": [
            {
                "id": event.id,
                "source": event.source,
                "event_type": event.event_type,
                "severity": event.severity,
                "hostname": event.hostname,
                "container_name": event.container_name,
                "raw_event_json": event.raw_event_json,
                "created_at": export_datetime(event.created_at),
            }
            for event in events
        ],
        "timeline": timeline,
        "enrichment": {
            "sources_seen": sorted(sources_seen),
            "hosts_seen": sorted(hosts_seen),
            "containers_seen": sorted(containers_seen),
            "event_types_seen": sorted(event_types_seen),
            "counts_by_source": counts_by_source,
            "counts_by_severity": counts_by_severity,
            "counts_by_event_type": counts_by_event_type,
            "first_activity": export_datetime(events[0].created_at) if events else None,
            "last_activity": export_datetime(events[-1].created_at) if events else None,
        },
    }

    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="netsentinel-incident-{incident_id}.json"'
        },
    )

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

@router.get("/export/csv", response_class=Response)
def export_incidents_csv(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    title_contains: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    statement = select(Incident)

    if status:
        statement = statement.where(Incident.status == status)

    if severity:
        statement = statement.where(Incident.severity == severity)

    if title_contains:
        statement = statement.where(Incident.title.ilike(f"%{title_contains}%"))

    statement = statement.order_by(Incident.last_seen.desc(), Incident.id.desc())

    incidents = db.execute(statement).scalars().all()

    buffer = StringIO()
    writer = csv.writer(buffer)

    writer.writerow(
        [
            "id",
            "title",
            "description",
            "severity",
            "status",
            "first_seen",
            "last_seen",
            "correlation_key",
        ]
    )

    for incident in incidents:
        writer.writerow(
            [
                incident.id,
                incident.title,
                incident.description,
                incident.severity,
                incident.status,
                incident.first_seen.isoformat() if incident.first_seen else "",
                incident.last_seen.isoformat() if incident.last_seen else "",
                incident.correlation_key,
            ]
        )

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="netsentinel-incidents.csv"'
        },
    )

@router.get("/{incident_id}/detail", response_model=IncidentDetailResponse)
def get_incident_detail(
    incident_id: int,
    db: DbSession,
    limit: int = Query(default=100, ge=1, le=500),
):
    incident = get_incident_or_404(db, incident_id)
    events = get_incident_linked_events(db, incident_id, limit=limit, newest_first=True)

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
    incident = get_incident_or_404(db, incident_id)
    events = get_incident_linked_events(db, incident_id, limit=limit, newest_first=False)

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


@router.get("/{incident_id}/enrichment", response_model=IncidentEnrichmentResponse)
def get_incident_enrichment(
    incident_id: int,
    db: DbSession,
    limit: int = Query(default=500, ge=1, le=2000),
):
    incident = get_incident_or_404(db, incident_id)
    events = get_incident_linked_events(db, incident_id, limit=limit, newest_first=False)

    sources = [event.source for event in events]
    severities = [event.severity for event in events]
    hosts = [event.hostname for event in events if event.hostname]
    containers = [event.container_name for event in events if event.container_name]
    event_types = [event.event_type for event in events]

    first_activity = events[0].created_at if events else None
    last_activity = events[-1].created_at if events else None

    return IncidentEnrichmentResponse(
        incident=incident,
        event_count=len(events),
        sources_seen=sorted(set(sources)),
        severities_seen=sorted(set(severities)),
        hosts_seen=sorted(set(hosts)),
        containers_seen=sorted(set(containers)),
        event_types_seen=sorted(set(event_types)),
        first_activity=first_activity,
        last_activity=last_activity,
        counts_by_source=dict(Counter(sources)),
        counts_by_severity=dict(Counter(severities)),
        counts_by_event_type=dict(Counter(event_types)),
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: DbSession):
    return get_incident_or_404(db, incident_id)


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: int, payload: IncidentUpdate, db: DbSession):
    incident = get_incident_or_404(db, incident_id)

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
    get_incident_or_404(db, incident_id)
    return get_incident_linked_events(db, incident_id, limit=limit, newest_first=True)