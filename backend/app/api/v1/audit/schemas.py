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
# NOTE : ce Literal sert de documentation/référence des types d'événements connus ;
# le champ `action` réel dans AuditLogOut reste un simple `str` (voir plus bas),
# pour ne jamais rejeter un événement d'audit à cause d'une valeur non encore listée ici.
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
    # Représente une entrée telle que renvoyée au client (voir write_audit_log
    # dans api/v1/auth/service.py pour la structure d'écriture correspondante).
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
    # Plafond dur à 100 000 lignes : protège contre un export qui tenterait
    # de dumper la totalité d'un historique de 7 ans en une seule requête.
    max_rows: int = Field(default=50_000, ge=1, le=100_000)


class FailedLoginsResponse(BaseModel):
    total: int
    from_date: Optional[str] = None
    to_date: Optional[str] = None
    results: List[AuditLogOut]
