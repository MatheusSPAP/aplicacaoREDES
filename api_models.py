"""Modelos públicos usados na documentação OpenAPI."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PageMeta(BaseModel):
    page: int = Field(ge=1)
    limit: int = Field(ge=1, le=1000)
    returned: int = Field(ge=0)


class PaginatedResponse(BaseModel):
    data: list[dict[str, Any]]
    pagination: PageMeta


class DataResponse(BaseModel):
    data: Any


class HealthResponse(BaseModel):
    status: str
    database: str
