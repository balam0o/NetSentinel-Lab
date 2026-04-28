from typing import Any

from pydantic import BaseModel, Field


class FalcoEventIngest(BaseModel):
    output: str = Field(min_length=1)
    priority: str = Field(min_length=1)
    rule: str = Field(min_length=1)
    output_fields: dict[str, Any] = Field(default_factory=dict)