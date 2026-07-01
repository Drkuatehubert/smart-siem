from __future__ import annotations

from pydantic import BaseModel, Field


class Report(BaseModel):
    id: str
    title: str
    format: str = Field(default="pdf")


class ReportFilter(BaseModel):
    format: str | None = None


class ReportGenerateRequest(BaseModel):
    title: str
    format: str = Field(default="pdf")
