"""
rbac.py — Contrôle d'accès basé sur les rôles (RBAC)
Responsable : Chef de Projet & Sécurité
Exigences couvertes : RF-SEC-02, RF-SEC-04
"""

from functools import wraps
from typing import List

from fastapi import Depends, HTTPException, status

from app.core.security import get_current_user

# ─────────────────────────────────────────────
# Définition des rôles
# ─────────────────────────────────────────────

class Role:
    LECTEUR       = "lecteur"
    ANALYSTE      = "analyste"
    ADMINISTRATEUR = "administrateur"

    ALL = [LECTEUR, ANALYSTE, ADMINISTRATEUR]


# ─────────────────────────────────────────────
# Matrice des permissions
# RF-SEC-02 : Lecteur < Analyste < Administrateur
# ─────────────────────────────────────────────

PERMISSIONS: dict[str, List[str]] = {
    # Logs
    "logs:read":          [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR],
    "logs:search":        [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR],
    "logs:ingest":        [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "logs:flag":          [Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Alertes
    "alerts:read":        [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR],
    "alerts:update":      [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "alerts:assign":      [Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Incidents
    "incidents:read":     [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR],
    "incidents:create":   [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "incidents:update":   [Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Playbooks SOAR
    "playbooks:execute":  [Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Rapports
    "reports:read":       [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR],
    "reports:generate":   [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "reports:export":     [Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Dashboard
    "dashboard:read":     [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR],

    # Audit log
    "audit:read":         [Role.ADMINISTRATEUR],

    # Utilisateurs (admin seulement)
    "users:read":         [Role.ADMINISTRATEUR],
    "users:create":       [Role.ADMINISTRATEUR],
    "users:update":       [Role.ADMINISTRATEUR],
    "users:delete":       [Role.ADMINISTRATEUR],

    # Règles de corrélation (admin seulement)
    "rules:read":         [Role.ANALYSTE, Role.ADMINISTRATEUR],
    "rules:create":       [Role.ADMINISTRATEUR],
    "rules:update":       [Role.ADMINISTRATEUR],
    "rules:delete":       [Role.ADMINISTRATEUR],

    # Sources / agents
    "sources:read":       [Role.LECTEUR, Role.ANALYSTE, Role.ADMINISTRATEUR],
    "sources:manage":     [Role.ADMINISTRATEUR],

    # Politique de rétention
    "retention:read":     [Role.ADMINISTRATEUR],
    "retention:update":   [Role.ADMINISTRATEUR],
}


# ─────────────────────────────────────────────
# Helpers de vérification
# ─────────────────────────────────────────────

def has_permission(role: str, permission: str) -> bool:
    """Vérifie si un rôle possède une permission donnée."""
    allowed_roles = PERMISSIONS.get(permission, [])
    return role in allowed_roles


def check_org_scope(user: dict, resource_org_scope: str) -> bool:
    """
    Vérifie la ségrégation organisationnelle (RF-SEC-04).
    Un admin voit tout. Les autres ne voient que leur périmètre.
    """
    if user.get("role") == Role.ADMINISTRATEUR:
        return True
    user_scope = user.get("org_scope")
    if user_scope is None:
        return True  # Pas de restriction si pas de scope défini
    return user_scope == resource_org_scope


# ─────────────────────────────────────────────
# Dépendances FastAPI injectables
# ─────────────────────────────────────────────

def require_roles(*roles: str):
    """
    Dépendance FastAPI : restreint l'accès aux rôles spécifiés.

    Usage :
        @router.get("/admin-only")
        async def endpoint(user=Depends(require_roles(Role.ADMINISTRATEUR))):
            ...
    """
    async def dependency(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Accès refusé. Rôle requis : {', '.join(roles)}"
            )
        return current_user
    return dependency


def require_permission(permission: str):
    """
    Dépendance FastAPI : vérifie une permission spécifique.

    Usage :
        @router.patch("/alerts/{id}")
        async def update_alert(user=Depends(require_permission("alerts:update"))):
            ...
    """
    async def dependency(current_user: dict = Depends(get_current_user)):
        role = current_user.get("role", "")
        if not has_permission(role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' requise"
            )
        return current_user
    return dependency


# Raccourcis pratiques
require_admin      = require_roles(Role.ADMINISTRATEUR)
require_analyste   = require_roles(Role.ANALYSTE, Role.ADMINISTRATEUR)
require_any_role   = require_roles(*Role.ALL)
