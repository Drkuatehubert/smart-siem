from typing import Optional, List, Dict, Any
from pydantic import BaseModel
class RuleCreate(BaseModel):
    # Définit une règle de corrélation évaluée par le moteur (voir correlation/ à la racine du projet).
    nom: str; description: Optional[str] = None
    type: str  # seuil / sequentielle — "seuil" = compte d'occurrences, "sequentielle" = suite d'événements ordonnée
    condition: Dict[str, Any]  # structure libre interprétée par le moteur de corrélation selon `type`
    fenetre_temporelle_s: int = 60  # durée (secondes) sur laquelle la condition est évaluée
    mitre_tactic: Optional[str] = None  # référence au framework MITRE ATT&CK, pour le classement des menaces
    niveau_alerte_genere: str = "HIGH"  # sévérité de l'alerte produite si la règle se déclenche
    active: bool = True  # permet de désactiver une règle sans la supprimer
class RuleOut(RuleCreate):
    id: str; created_by: Optional[str] = None
class RuleListResponse(BaseModel):
    total: int; page: int; size: int; results: List[RuleOut]
