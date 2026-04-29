from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Event, Incident, IncidentEvent

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

DEFAULT_CORRELATION_WINDOW_HOURS = 24


def correlate_event(db: Session, event: Event) -> Incident | None:
    if event.severity not in {"high", "critical"}:
        return None

    correlation_key = build_correlation_key(event)

    statement = (
        select(Incident)
        .where(Incident.correlation_key == correlation_key)
        .order_by(Incident.last_seen.desc(), Incident.id.desc())
    )

    existing_incident = db.execute(statement).scalars().first()

    if existing_incident is not None:
        if is_within_correlation_window(existing_incident.last_seen, event.created_at):
            existing_incident.last_seen = event.created_at

            if existing_incident.status == "closed":
                existing_incident.status = "open"

            if severity_rank(event.severity) > severity_rank(existing_incident.severity):
                existing_incident.severity = event.severity

            link_event_to_incident(db, existing_incident, event)
            db.commit()
            db.refresh(existing_incident)
            return existing_incident

    incident = Incident(
        title=build_incident_title(event),
        description=build_incident_description(event),
        severity=event.severity,
        status="open",
        correlation_key=correlation_key,
        first_seen=event.created_at,
        last_seen=event.created_at,
    )

    db.add(incident)
    db.flush()

    link_event_to_incident(db, incident, event)

    db.commit()
    db.refresh(incident)
    return incident


def build_incident_title(event: Event) -> str:
    host = event.hostname or "unknown-host"
    container = event.container_name or "unknown-container"
    return f"{event.event_type} on {host}/{container}"


def build_incident_description(event: Event) -> str:
    return (
        f"Incident created from {event.source} event '{event.event_type}' "
        f"with severity '{event.severity}'."
    )


def build_correlation_key(event: Event) -> str:
    host = event.hostname or "-"
    container = event.container_name or "-"
    return f"{event.source}:{event.event_type}:{host}:{container}"


def severity_rank(value: str) -> int:
    return SEVERITY_RANK.get(value, 0)


def ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def get_correlation_window_hours() -> int:
    raw_value = os.getenv("CORRELATION_WINDOW_HOURS", str(DEFAULT_CORRELATION_WINDOW_HOURS))

    try:
        hours = int(raw_value)
    except ValueError:
        return DEFAULT_CORRELATION_WINDOW_HOURS

    return max(1, hours)


def get_correlation_window() -> timedelta:
    return timedelta(hours=get_correlation_window_hours())


def is_within_correlation_window(last_seen: datetime, event_created_at: datetime) -> bool:
    last_seen_utc = ensure_utc(last_seen)
    event_created_at_utc = ensure_utc(event_created_at)
    delta = event_created_at_utc - last_seen_utc
    return delta <= get_correlation_window()


def link_event_to_incident(db: Session, incident: Incident, event: Event) -> None:
    existing_link = db.get(
        IncidentEvent,
        {"incident_id": incident.id, "event_id": event.id},
    )
    if existing_link is None:
        db.add(
            IncidentEvent(
                incident_id=incident.id,
                event_id=event.id,
            )
        )