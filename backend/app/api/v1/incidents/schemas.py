from typing import Optional, List
from pydantic import BaseModel

class IncidentCreate(BaseModel):
    # Corps de requête pour créer un incident, éventuellement à partir d'une alerte existante.
    alert_id: Optional[str] = None      # alerte à l'origine de l'incident (si applicable)
    titre: str
    description: Optional[str] = None
    statut: str = "ouvert"
    priorite: str = "P3"  # P1 (critique) à P4 (mineure), convention courante en gestion d'incident

class IncidentOut(IncidentCreate):
    # Hérite des champs de création et ajoute les métadonnées générées côté serveur.
    id: str
    owner: Optional[str] = None         # analyste responsable de l'incident
    created_at: str
    updated_at: str

class IncidentListResponse(BaseModel):
    total: int; page: int; size: int; results: List[IncidentOut]
