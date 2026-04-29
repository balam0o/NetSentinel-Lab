from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

import app.core.settings as settings
from app.db.models import Event, Incident, IncidentEvent

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def correlate_event(db: Session, event: Event) -> Incident | None:
    if event.severity in {"high", "critical"}:
        return correlate_high_or_critical_event(db, event)

    if event.severity == "medium":
        return correlate_medium_event(db, event)

    return None


def correlate_high_or_critical_event(db: Session, event: Event) -> Incident | None:
    correlation_key = build_correlation_key(event)
    existing_incident = get_latest_matching_incident(db, correlation_key)
    chain_precursors = get_recent_chain_precursor_events(db, event)
    target_severity = derive_attack_chain_severity(event, chain_precursors)
    target_description = (
        build_attack_chain_incident_description(event, chain_precursors)
        if chain_precursors
        else build_incident_description(event)
    )

    if existing_incident is not None:
        if is_within_correlation_window(existing_incident.last_seen, event.created_at):
            existing_incident.last_seen = event.created_at

            if existing_incident.status == "closed":
                existing_incident.status = "open"

            if severity_rank(target_severity) > severity_rank(existing_incident.severity):
                existing_incident.severity = target_severity

            if chain_precursors:
                existing_incident.description = target_description

            for precursor in chain_precursors:
                link_event_to_incident(db, existing_incident, precursor)

            link_event_to_incident(db, existing_incident, event)
            db.commit()
            db.refresh(existing_incident)
            return existing_incident

    incident = create_incident(
        db=db,
        event=event,
        severity=target_severity,
        description=target_description,
    )

    for precursor in chain_precursors:
        link_event_to_incident(db, incident, precursor)

    link_event_to_incident(db, incident, event)

    db.commit()
    db.refresh(incident)
    return incident


def correlate_medium_event(db: Session, event: Event) -> Incident | None:
    correlation_key = build_correlation_key(event)
    existing_incident = get_latest_matching_incident(db, correlation_key)

    if existing_incident is not None:
        if is_within_correlation_window(existing_incident.last_seen, event.created_at):
            existing_incident.last_seen = event.created_at

            if existing_incident.status == "closed":
                existing_incident.status = "open"

            link_event_to_incident(db, existing_incident, event)
            db.commit()
            db.refresh(existing_incident)
            return existing_incident

    recent_medium_events = get_recent_matching_medium_events(db, event)

    if not qualifies_for_medium_burst(recent_medium_events):
        return None

    incident = create_incident(
        db=db,
        event=event,
        severity="high",
        description=build_medium_burst_incident_description(event, len(recent_medium_events)),
    )

    for related_event in recent_medium_events:
        link_event_to_incident(db, incident, related_event)

    db.commit()
    db.refresh(incident)
    return incident


def get_latest_matching_incident(db: Session, correlation_key: str) -> Incident | None:
    statement = (
        select(Incident)
        .where(Incident.correlation_key == correlation_key)
        .order_by(Incident.last_seen.desc(), Incident.id.desc())
    )
    return db.execute(statement).scalars().first()


def create_incident(
    db: Session,
    event: Event,
    severity: str,
    description: str,
) -> Incident:
    incident = Incident(
        title=build_incident_title(event),
        description=description,
        severity=severity,
        status="open",
        correlation_key=build_correlation_key(event),
        first_seen=event.created_at,
        last_seen=event.created_at,
    )
    db.add(incident)
    db.flush()
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


def build_medium_burst_incident_description(event: Event, count: int) -> str:
    return (
        f"Incident created from repeated medium-severity {event.source} events "
        f"for '{event.event_type}' ({count} events within "
        f"{get_medium_burst_window_minutes()} minutes)."
    )


def build_attack_chain_incident_description(event: Event, precursors: list[Event]) -> str:
    precursor_types = ", ".join(sorted({precursor.event_type for precursor in precursors}))
    return (
        f"Incident elevated by attack-chain correlation: {precursor_types} "
        f"preceded '{event.event_type}' within {get_attack_chain_window_minutes()} minutes."
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
    return settings.get_correlation_window_hours()


def get_correlation_window() -> timedelta:
    return timedelta(hours=get_correlation_window_hours())


def get_medium_burst_threshold() -> int:
    return settings.get_medium_burst_threshold()


def get_medium_burst_window_minutes() -> int:
    return settings.get_medium_burst_window_minutes()


def get_medium_burst_window() -> timedelta:
    return timedelta(minutes=get_medium_burst_window_minutes())


def get_attack_chain_window_minutes() -> int:
    return settings.get_attack_chain_window_minutes()


def get_attack_chain_window() -> timedelta:
    return timedelta(minutes=get_attack_chain_window_minutes())


def is_within_correlation_window(last_seen: datetime, event_created_at: datetime) -> bool:
    last_seen_utc = ensure_utc(last_seen)
    event_created_at_utc = ensure_utc(event_created_at)
    delta = event_created_at_utc - last_seen_utc
    return delta <= get_correlation_window()


def get_recent_matching_medium_events(db: Session, event: Event) -> list[Event]:
    threshold = get_medium_burst_threshold()

    statement = (
        select(Event)
        .where(
            Event.source == event.source,
            Event.event_type == event.event_type,
            nullable_match(Event.hostname, event.hostname),
            nullable_match(Event.container_name, event.container_name),
            Event.severity == "medium",
        )
        .order_by(Event.created_at.desc(), Event.id.desc())
        .limit(threshold)
    )

    events = db.execute(statement).scalars().all()
    events.reverse()
    return events


def qualifies_for_medium_burst(events: list[Event]) -> bool:
    threshold = get_medium_burst_threshold()

    if len(events) < threshold:
        return False

    first_event_time = ensure_utc(events[0].created_at)
    last_event_time = ensure_utc(events[-1].created_at)

    return (last_event_time - first_event_time) <= get_medium_burst_window()


def get_attack_chain_precursor_types(event: Event) -> list[str]:
    if event.event_type == "credential_access":
        return ["port_scan_detected"]

    if event.event_type == "reverse_shell_detected":
        return ["port_scan_detected", "credential_access"]

    return []


def get_recent_chain_precursor_events(db: Session, event: Event) -> list[Event]:
    precursor_types = get_attack_chain_precursor_types(event)

    if not precursor_types:
        return []

    event_created_at_utc = ensure_utc(event.created_at)
    window = get_attack_chain_window()

    statement = (
        select(Event)
        .where(
            Event.id != event.id,
            Event.source == event.source,
            Event.event_type.in_(precursor_types),
            nullable_match(Event.hostname, event.hostname),
            nullable_match(Event.container_name, event.container_name),
        )
        .order_by(Event.created_at.desc(), Event.id.desc())
        .limit(20)
    )

    candidates = db.execute(statement).scalars().all()
    candidates.reverse()

    matched = []
    for candidate in candidates:
        candidate_created_at_utc = ensure_utc(candidate.created_at)
        delta = event_created_at_utc - candidate_created_at_utc

        if timedelta(0) <= delta <= window:
            matched.append(candidate)

    return matched


def derive_attack_chain_severity(event: Event, precursors: list[Event]) -> str:
    if precursors:
        return "critical"
    return event.severity


def nullable_match(column, value):
    if value is None:
        return column.is_(None)
    return column == value


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