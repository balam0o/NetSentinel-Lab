from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas.stats import StatsSummaryResponse
from app.db.models import Event, Incident
from app.db.session import get_db

router = APIRouter(prefix="/stats", tags=["stats"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("/summary", response_model=StatsSummaryResponse)
def get_stats_summary(db: DbSession):
    total_events = db.execute(
        select(func.count()).select_from(Event)
    ).scalar_one()

    total_incidents = db.execute(
        select(func.count()).select_from(Incident)
    ).scalar_one()

    open_incidents = db.execute(
        select(func.count()).select_from(Incident).where(Incident.status == "open")
    ).scalar_one()

    incident_rows = db.execute(
        select(Incident.severity, func.count())
        .group_by(Incident.severity)
        .order_by(Incident.severity)
    ).all()

    event_rows = db.execute(
        select(Event.source, func.count())
        .group_by(Event.source)
        .order_by(Event.source)
    ).all()

    incidents_by_severity = {severity: count for severity, count in incident_rows}
    events_by_source = {source: count for source, count in event_rows}

    return StatsSummaryResponse(
        total_events=total_events,
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        incidents_by_severity=incidents_by_severity,
        events_by_source=events_by_source,
    )