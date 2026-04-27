from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Event, Incident, IncidentEvent


def correlate_event(db: Session, event: Event) -> Incident | None:
    """
    Simple correlation rules for phase 3.

    Rules:
    - high/critical severity events create or update an open incident
      grouped by event_type + hostname + container_name
    - medium/low events do not create incidents yet
    """

    if event.severity not in {"high", "critical"}:
        return None

    statement = (
        select(Incident)
        .where(Incident.status == "open")
        .where(Incident.title == build_incident_title(event))
        .order_by(Incident.last_seen.desc())
    )

    existing_incident = db.execute(statement).scalars().first()

    if existing_incident:
        existing_incident.last_seen = event.created_at
        link_event_to_incident(db, existing_incident, event)
        db.commit()
        db.refresh(existing_incident)
        return existing_incident

    incident = Incident(
        title=build_incident_title(event),
        description=build_incident_description(event),
        severity=event.severity,
        status="open",
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