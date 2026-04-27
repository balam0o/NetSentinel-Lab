from pydantic import BaseModel


class StatsSummaryResponse(BaseModel):
    total_events: int
    total_incidents: int
    open_incidents: int
    incidents_by_severity: dict[str, int]
    events_by_source: dict[str, int]