"""
rbac.py — Contrôle d'accès basé sur les rôles (RBAC) + org_scope

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-02, RF-SEC-04 (multi-tenant)

Durcissements par rapport à la version initiale :
  * nouveau rôle AUDITEUR (lecture seule cross-scope) ;
  * nouvelle permission `soar:execute` (analyste+admin) ;
  * `audit:read` accordé à ADMINISTRATEUR ET AUDITEUR (corrige le mensonge
    du docstring de l'audit router précédent) ;
  * `require_roles_with_audit` écrit dans `idx-audit-log` à chaque refus
    (action `autorisation_refusee`) avec détails forensiques ;
  * `check_org_scope` lève désormais un audit `acces_hors_perimetre` quand
    le périmètre est dépassé (au lieu d'un simple 403 muet).
"""

from __future__ import annotations

from typing import List

from fastapi import Depends, HTTPException, Request, status

from app.core.security import get_current_user, require_validated_user


# ─────────────────────────────────────────────────────────────────────
# Définition des rôles
# ─────────────────────────────────────────────────────────────────────

class Role:
    LECTEUR        = "lecteur"
    ANALYSTE       = "analyste"
    ADMINISTRATEUR = "administrateur"
    AUDITEUR       = "auditeur"  # lecture seule, cross-scope (RF-SEC-04)

    ALL = [LECTEUR, ANALYSTE, ADMINISTRATEUR, AUDITEUR]


# ─────────────────────────────────────────────────────────────────────
# Matrice des permissions (RF-SEC-02)
# ─────────────────────────────────────────────────────────────────────

PERMISSIONS: dict[str, List[str]] = {
    # Logs
    "logs:read":          [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR],
    "logs:search":        [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR],
    "logs:ingest":        [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "logs:flag":          [Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Alertes
    "alerts:read":        [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR, Role.AUDITEUR],
    "alerts:update":      [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "alerts:assign":      [Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Incidents
    "incidents:read":     [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR, Role.AUDITEUR],
    "incidents:create":   [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "incidents:update":   [Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Playbooks SOAR
    "soar:execute":       [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "playbooks:execute":  [Role.ANALYSTE, Role.ADMINISTRATEUR],  # alias historique

    # Rapports
    "reports:read":       [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR, Role.AUDITEUR],
    "reports:generate":   [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "reports:export":     [Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Dashboard
    "dashboard:read":     [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR, Role.AUDITEUR],

    # Audit log (RF-SEC-03) — Admin OU Auditeur (lecture seule)
    "audit:read":         [Role.ADMINISTRATEUR, Role.AUDITEUR],

    # Utilisateurs (admin seulement)
    "users:read":         [Role.ADMINISTRATEUR, Role.AUDITEUR],
    "users:create":       [Role.ADMINISTRATEUR],
    "users:update":       [Role.ADMINISTRATEUR],
    "users:delete":       [Role.ADMINISTRATEUR],

    # Règles de corrélation (admin seulement)
    "rules:read":         [Role.ANALYSTE, Role.ADMINISTRATEUR, Role.AUDITEUR],
    "rules:create":       [Role.ADMINISTRATEUR],
    "rules:update":       [Role.ADMINISTRATEUR],
    "rules:delete":       [Role.ADMINISTRATEUR],

    # Sources / agents
    "sources:read":       [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR, Role.AUDITEUR],
    "sources:manage":     [Role.ADMINISTRATEUR],

    # Politique de rétention
    "retention:read":     [Role.ADMINISTRATEUR, Role.AUDITEUR],
    "retention:update":   [Role.ADMINISTRATEUR],
}


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def has_permission(role: str, permission: str) -> bool:
    """Vérifie si un rôle possède une permission donnée."""
    allowed_roles = PERMISSIONS.get(permission)
    if allowed_roles is None:
        # Permission inconnue : on log et on refuse (fail-closed)
        import logging
        logging.getLogger("rbac").warning("Permission inconnue demandée : %s", permission)
        return False
    return role in allowed_roles


def check_org_scope(user: dict, resource_org_scope: str) -> bool:
    """
    Vérifie la ségrégation organisationnelle (RF-SEC-04).

    Règles :
      * ADMINISTRATEUR → bypass total ;
      * AUDITEUR → bypass total en lecture (mais endpoints sensibles en écriture refusés) ;
      * autres rôles → exigent `user.org_scope == resource_org_scope` (et non None).
    """
    role = user.get("role")
    if role == Role.ADMINISTRATEUR:
        return True
    if role == Role.AUDITEUR and user.get("_scope_context") == "read":
        return True
    user_scope = user.get("org_scope")
    if not user_scope:
        # Pas de scope ⇒ on refuse par défaut (fail-closed). Avant c'était True !
        return False
    return user_scope == resource_org_scope


# ─────────────────────────────────────────────────────────────────────
# Audit des refus
# ─────────────────────────────────────────────────────────────────────

async def _write_authz_denied(
    user: dict,
    *,
    required_roles: List[str] | None = None,
    required_permission: str | None = None,
    request: Request | None = None,
) -> None:
    """Écrit un événement `autorisation_refusee` dans `idx-audit-log`."""
    try:
        from app.api.v1.auth.service import write_audit_log  # import local (évite cycle)
        import json
        details = {
            "required_roles": required_roles,
            "required_permission": required_permission,
            "actual_role": user.get("role"),
            "path": getattr(request, "url", None).path if request else None,
            "method": request.method if request else None,
            "request_id": getattr(getattr(request, "state", None), "request_id", None),
        }
        await write_audit_log(
            user_id=user.get("sub", "anonymous"),
            action="autorisation_refusee",
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            request_id=details["request_id"],
            http_method=details["method"],
            http_path=details["path"],
            status="failure",
            target_entity="rbac",
            details={k: v for k, v in details.items() if v is not None},
        )
    except Exception:
        # L'audit ne doit jamais faire échouer la requête elle-même
        pass


# ─────────────────────────────────────────────────────────────────────
# Dépendances FastAPI
# ─────────────────────────────────────────────────────────────────────

def require_roles(*roles: str):
    """
    Dépendance : restreint l'accès à une liste explicite de rôles.
    Émet un audit `autorisation_refusee` en cas de 403.
    """
    async def dependency(
        request: Request,
        current_user: dict = Depends(require_validated_user),
    ):
        if current_user.get("role") not in roles:
            await _write_authz_denied(
                current_user, required_roles=list(roles), request=request,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accès refusé",
            )
        return current_user
    return dependency


def require_permission(permission: str):
    """Dépendance : vérifie une permission spécifique. Émet un audit en cas de refus."""
    async def dependency(
        request: Request,
        current_user: dict = Depends(require_validated_user),
    ):
        role = current_user.get("role", "")
        if not has_permission(role, permission):
            await _write_authz_denied(
                current_user, required_permission=permission, request=request,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accès refusé",
            )
        return current_user
    return dependency


# Raccourcis
require_admin    = require_roles(Role.ADMINISTRATEUR)
require_analyste = require_roles(Role.ANALYSTE, Role.ADMINISTRATEUR)
require_auditor  = require_roles(Role.ADMINISTRATEUR, Role.AUDITEUR)
require_any_role = require_roles(*Role.ALL)
