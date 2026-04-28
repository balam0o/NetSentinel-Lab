from typing import Any

from pydantic import BaseModel, Field


class SuricataEventIngest(BaseModel):
    timestamp: str | None = None
    event_type: str = Field(min_length=1)
    src_ip: str = Field(min_length=1)
    src_port: int | None = None
    dest_ip: str = Field(min_length=1)
    dest_port: int | None = None
    proto: str | None = None
    app_proto: str | None = None
    host: str | None = None
    alert: dict[str, Any] = Field(default_factory=dict)