from typing import Optional
from pydantic import BaseModel
class ReportRequest(BaseModel):
    type: str = "weekly"
    from_date: str; to_date: str; format: str = "pdf"
class ReportOut(BaseModel):
    id: str; status: str; download_url: Optional[str] = None
