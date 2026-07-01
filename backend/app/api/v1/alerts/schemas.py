"""alerts/schemas.py"""
from typing import Optional, List
from pydantic import BaseModel

class AlertOut(BaseModel):
    # Représente une alerte remontée par le moteur de corrélation (voir
    # correlation/ à la racine du projet), stockée dans l'index Elasticsearch idx-alerts.
    id: str
    rule_id: Optional[str] = None       # règle de corrélation à l'origine de l'alerte (si applicable)
    log_refs: List[str] = []            # identifiants des logs bruts ayant déclenché l'alerte
    niveau: str  # INFO / WARNING / HIGH / CRITICAL
    statut: str  # ouvert / en_cours / resolu
    assigned_to: Optional[str] = None   # analyste en charge du traitement
    score_risque: Optional[int] = None
    created_at: str
    updated_at: str
    commentaires: Optional[str] = None

class AlertStatusUpdate(BaseModel):
    # Corps de requête pour faire évoluer le traitement d'une alerte (PATCH /alerts/{id}/status).
    statut: str
    assigned_to: Optional[str] = None
    commentaires: Optional[str] = None

class AlertListResponse(BaseModel):
    total: int
    page: int
    size: int
    results: List[AlertOut]
