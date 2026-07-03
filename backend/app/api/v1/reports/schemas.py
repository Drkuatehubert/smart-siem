from typing import Optional
from pydantic import BaseModel
class ReportRequest(BaseModel):
    type: str = "weekly"  # ex: weekly / monthly / incident — type de rapport à générer
    from_date: str; to_date: str; format: str = "pdf"
class ReportOut(BaseModel):
    # download_url reste None tant que le rapport est en cours de génération (status="queued").
    id: str; status: str; download_url: Optional[str] = None
