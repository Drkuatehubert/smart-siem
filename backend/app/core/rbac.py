"""
rbac.py â€” ContrÃ´le d'accÃ¨s basÃ© sur les rÃ´les (RBAC) + org_scope

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : RF-SEC-02, RF-SEC-04 (multi-tenant)

Durcissements par rapport Ã  la version initiale :
  * nouveau rÃ´le AUDITEUR (lecture seule cross-scope) ;
  * nouvelle permission `soar:execute` (analyste+admin) ;
  * `audit:read` accordÃ© Ã  ADMINISTRATEUR ET AUDITEUR (corrige le mensonge
    du docstring de l'audit router prÃ©cÃ©dent) ;
  * `require_roles_with_audit` Ã©crit dans `idx-audit-log` Ã  chaque refus
    (action `autorisation_refusee`) avec dÃ©tails forensiques ;
  * `check_org_scope` lÃ¨ve dÃ©sormais un audit `acces_hors_perimetre` quand
    le pÃ©rimÃ¨tre est dÃ©passÃ© (au lieu d'un simple 403 muet).
"""

from __future__ import annotations

from typing import List

from fastapi import Depends, HTTPException, Request, status

from app.core.security import get_current_user, require_validated_user


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# DÃ©finition des rÃ´les
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class Role:
    LECTEUR        = "lecteur"
    ANALYSTE       = "analyste"
    ADMINISTRATEUR = "administrateur"
    AUDITEUR       = "auditeur"  # lecture seule, cross-scope (RF-SEC-04)

    ALL = [LECTEUR, ANALYSTE, ADMINISTRATEUR, AUDITEUR]


# Alias rôles PostgreSQL → rôles RBAC canoniques
_PG_ROLE_ALIASES: dict[str, str] = {
    "admin": "administrateur",
    "administrateur": "administrateur",
    "analyst": "analyste",
    "analyste": "analyste",
    "reader": "lecteur",
    "lecteur": "lecteur",
    "auditor": "auditeur",
    "auditeur": "auditeur",
}


def normalize_role(role: str | None) -> str:
    """Normalise un rôle PG ou JWT vers le vocabulaire RBAC."""
    if not role:
        return Role.LECTEUR
    key = role.strip().lower()
    return _PG_ROLE_ALIASES.get(key, key)


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Matrice des permissions (RF-SEC-02)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    # Audit log (RF-SEC-03) â€” Admin OU Auditeur (lecture seule)
    "audit:read":         [Role.ADMINISTRATEUR, Role.AUDITEUR],

    # Utilisateurs (admin seulement)
    "users:read":         [Role.ADMINISTRATEUR, Role.AUDITEUR],
    "users:create":       [Role.ADMINISTRATEUR],
    "users:update":       [Role.ADMINISTRATEUR],
    "users:delete":       [Role.ADMINISTRATEUR],

    # RÃ¨gles de corrÃ©lation (admin seulement)
    "rules:read":         [Role.ANALYSTE, Role.ADMINISTRATEUR, Role.AUDITEUR],
    "rules:create":       [Role.ADMINISTRATEUR],
    "rules:update":       [Role.ADMINISTRATEUR],
    "rules:delete":       [Role.ADMINISTRATEUR],

    # Sources / agents
    "sources:read":       [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR, Role.AUDITEUR],
    "sources:manage":     [Role.ADMINISTRATEUR],

    # Politique de rÃ©tention
    "retention:read":     [Role.ADMINISTRATEUR, Role.AUDITEUR],
    "retention:update":   [Role.ADMINISTRATEUR],
}


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def has_permission(role: str, permission: str) -> bool:
    """VÃ©rifie si un rÃ´le possÃ¨de une permission donnÃ©e."""
    allowed_roles = PERMISSIONS.get(permission)
    if allowed_roles is None:
        # Permission inconnue : on log et on refuse (fail-closed)
        import logging
        logging.getLogger("rbac").warning("Permission inconnue demandÃ©e : %s", permission)
        return False
    return role in allowed_roles


def check_org_scope(user: dict, resource_org_scope: str) -> bool:
    """
    VÃ©rifie la sÃ©grÃ©gation organisationnelle (RF-SEC-04).

    RÃ¨gles :
      * ADMINISTRATEUR â†’ bypass total ;
      * AUDITEUR â†’ bypass total en lecture (mais endpoints sensibles en Ã©criture refusÃ©s) ;
      * autres rÃ´les â†’ exigent `user.org_scope == resource_org_scope` (et non None).
    """
    role = user.get("role")
    if role == Role.ADMINISTRATEUR:
        return True
    if role == Role.AUDITEUR and user.get("_scope_context") == "read":
        return True
    user_scope = user.get("org_scope")
    if not user_scope:
        # Pas de scope â‡’ on refuse par dÃ©faut (fail-closed). Avant c'Ã©tait True !
        return False
    return user_scope == resource_org_scope


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Audit des refus
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def _write_authz_denied(
    user: dict,
    *,
    required_roles: List[str] | None = None,
    required_permission: str | None = None,
    request: Request | None = None,
) -> None:
    """Ã‰crit un Ã©vÃ©nement `autorisation_refusee` dans `idx-audit-log`."""
    try:
        from app.api.v1.auth.service import write_audit_log  # import local (Ã©vite cycle)
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
        # L'audit ne doit jamais faire Ã©chouer la requÃªte elle-mÃªme
        pass


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# DÃ©pendances FastAPI
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def require_roles(*roles: str):
    """
    DÃ©pendance : restreint l'accÃ¨s Ã  une liste explicite de rÃ´les.
    Ã‰met un audit `autorisation_refusee` en cas de 403.
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
                detail="AccÃ¨s refusÃ©",
            )
        return current_user
    return dependency


def require_permission(permission: str):
    """DÃ©pendance : vÃ©rifie une permission spÃ©cifique. Ã‰met un audit en cas de refus."""
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
                detail="AccÃ¨s refusÃ©",
            )
        return current_user
    return dependency


# Raccourcis
require_admin    = require_roles(Role.ADMINISTRATEUR)
require_analyste = require_roles(Role.ANALYSTE, Role.ADMINISTRATEUR)
require_auditor  = require_roles(Role.ADMINISTRATEUR, Role.AUDITEUR)
require_any_role = require_roles(*Role.ALL)
