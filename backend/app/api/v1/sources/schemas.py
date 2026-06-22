from typing import Optional, List
from pydantic import BaseModel
class SourceCreate(BaseModel):
    nom: str; type: str
    adresse_ip: Optional[str] = None
    environnement: Optional[str] = None
    statut_collecte: str = "actif"
class SourceOut(SourceCreate):
    id: str; derniere_reception: Optional[str] = None
class SourceListResponse(BaseModel):
    total: int; page: int; size: int; results: List[SourceOut]
