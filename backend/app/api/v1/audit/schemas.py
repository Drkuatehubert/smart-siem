"""
schemas.py — Schémas Pydantic pour le journal d'audit (durcis)

Responsable : Chef de Projet & Sécurité
Index : idx-audit-log (append-only, ILM 7 ans)
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


# Valeurs autorisées pour `action` (énumération ouverte, énum étendue via Literal).
# Toute autre valeur est acceptée mais tagged `unknown` côté affichage.
AuditAction = Literal[
    "connexion",
    "connexion_reussie",
    "connexion_echouee",
    "deconnexion",
    "compte_verrouille",
    "reset_mdp_demande",
    "reset_mdp_confirme",
    "changement_mdp",
    "changement_mdp_echec",
    "mfa_setup_initie",
    "mfa_active",
    "mfa_code_invalide",
    "creation_utilisateur",
    "modification_utilisateur",
    "suppression_utilisateur",
    "utilisateur_desactive",
    "utilisateur_reactive",
    "autorisation_refusee",
    "acces_hors_perimetre",
    "consultation_alerte",
    "traitement_alerte",
    "modification_role",
    "soar_playbook_execute",
    "soar_playbook_echec",
    "soar_kill_switch_active",
    "export_audit",
]


class AuditLogOut(BaseModel):
    id: str
    user_id: str
    action: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    target_entity: Optional[str] = None
    target_id: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    status: str = "success"
    details: Optional[dict] = None
    created_at: str


class AuditLogListResponse(BaseModel):
    total: int
    page: int
    size: int
    results: List[AuditLogOut]


class AuditExportRequest(BaseModel):
    format: Literal["csv", "jsonl"] = "csv"
    from_date: Optional[str] = None
    to_date: Optional[str] = None
    max_rows: int = Field(default=50_000, ge=1, le=100_000)


class FailedLoginsResponse(BaseModel):
    total: int
    from_date: Optional[str] = None
    to_date: Optional[str] = None
    results: List[AuditLogOut]
