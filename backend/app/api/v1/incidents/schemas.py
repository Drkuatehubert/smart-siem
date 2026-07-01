from typing import Optional, List
from pydantic import BaseModel
class IncidentCreate(BaseModel):
    alert_id: Optional[str] = None
    titre: str
    description: Optional[str] = None
    statut: str = "ouvert"
    priorite: str = "P3"
class IncidentOut(IncidentCreate):
    id: str
    owner: Optional[str] = None
    created_at: str
    updated_at: str
class IncidentListResponse(BaseModel):
    total: int; page: int; size: int; results: List[IncidentOut]
