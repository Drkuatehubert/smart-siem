from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class RuleCreate(BaseModel):
    nom: str
    description: Optional[str] = None
    type: str
    condition: Dict[str, Any]
    fenetre_temporelle_s: int = 60
    mitre_tactic: Optional[str] = None
    niveau_alerte_genere: str = "HIGH"
    active: bool = True


class RuleOut(BaseModel):
    """Schéma de sortie aligné sur les colonnes PostgreSQL de correlation_rules."""
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    rule_type: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    time_window_seconds: Optional[int] = None
    threshold_count: Optional[int] = None
    alert_level: Optional[str] = None
    confidence_score: Optional[int] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    is_active: bool = True
    created_by: Optional[str] = None


class RuleListResponse(BaseModel):
    total: int
    items: List[RuleOut]
