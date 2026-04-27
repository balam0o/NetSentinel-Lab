from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.schemas.incidents import IncidentResponse
from app.db.models import Incident
from app.db.session import get_db

router = APIRouter(prefix="/incidents", tags=["incidents"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
):
    statement = select(Incident).order_by(desc(Incident.last_seen)).limit(limit)
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