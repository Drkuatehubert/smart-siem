from typing import Optional, List
from pydantic import BaseModel
class SourceCreate(BaseModel):
    # Représente une source de logs (serveur, pare-feu, agent...) enregistrée dans le SIEM.
    nom: str; type: str  # type de source (ex: "firewall", "windows", "linux", "application"...)
    adresse_ip: Optional[str] = None
    environnement: Optional[str] = None  # ex: "production", "staging"
    statut_collecte: str = "actif"       # "actif" / "inactif" : la collecte est-elle en cours pour cette source
class SourceOut(SourceCreate):
    id: str; derniere_reception: Optional[str] = None  # horodatage du dernier log reçu de cette source
class SourceListResponse(BaseModel):
    total: int; page: int; size: int; results: List[SourceOut]
