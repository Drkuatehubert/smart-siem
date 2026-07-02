from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class RuleCreate(BaseModel):
    nom: str
    description: Optional[str] = None
    type: str  # seuil / sequentielle
    condition: Dict[str, Any]
    fenetre_temporelle_s: int = 60
    mitre_tactic: Optional[str] = None
    niveau_alerte_genere: str = "HIGH"
    active: bool = True


class RuleOut(RuleCreate):
    id: str
    created_by: Optional[str] = None


class RuleListResponse(BaseModel):
    total: int
    page: int
    size: int
    results: List[RuleOut]
