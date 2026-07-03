"""
schemas.py — Schémas Pydantic pour la gestion des utilisateurs (durcis)

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-02, RF-SEC-04

Durcissements par rapport à la version initiale :
  * `role_id` est une `Literal[...]` ⇒ impossible de créer un utilisateur
    avec un rôle non reconnu (anti privilege-escalation) ;
  * `password` a des bornes explicites et la politique `PASSWORD_*` est appliquée ;
  * nouveaux schémas `UserUpdate`, `SetActiveRequest` ;
  * `UserOut` n'expose jamais `password_hash` ni `password_history`.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.api.v1.auth.schemas import _validate_password_strength
from app.core.rbac import Role


class UserCreate(BaseModel):
    """Création d'un utilisateur (admin uniquement)."""
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9._-]+$")
    email: Optional[EmailStr] = None
    password: str = Field(..., min_length=1, max_length=4096)
    # Literal[...] plutôt que `str` : Pydantic refuse toute valeur hors de cette liste,
    # empêchant qu'un rôle mal orthographié ou inventé soit accepté silencieusement.
    role_id: Literal["lecteur", "analyste", "administrateur", "auditeur"] = Role.LECTEUR
    org_scope: Optional[str] = Field(default=None, max_length=64)

    @field_validator("password")
    @classmethod
    def _check_strength(cls, v: str) -> str:
        # Réutilise la même politique de robustesse que le changement de mot de passe
        # (voir api/v1/auth/schemas.py) : un seul endroit définit ce qu'est "un mot de passe valide".
        return _validate_password_strength(v)


class UserUpdate(BaseModel):
    """Mise à jour partielle (PATCH /users/{id}). Tous champs optionnels."""
    # Tous les champs sont optionnels : seuls ceux effectivement fournis par le client
    # (via `model_dump(exclude_unset=True)` côté router) sont appliqués en base.
    email: Optional[EmailStr] = None
    role_id: Optional[Literal["lecteur", "analyste", "administrateur", "auditeur"]] = None
    org_scope: Optional[str] = Field(default=None, max_length=64)
    is_active: Optional[bool] = None


class SetActiveRequest(BaseModel):
    is_active: bool


class UserOut(BaseModel):
    """Sortie publique — ne JAMAIS inclure password_hash."""
    # Ce modèle sert de "liste blanche" des champs exposables : même si le document
    # Elasticsearch sous-jacent contient plus de champs (dont des sensibles),
    # seuls ceux déclarés ici peuvent atteindre le client.
    id: str
    username: str
    email: Optional[EmailStr] = None
    role_id: str
    org_scope: Optional[str] = None
    is_active: bool
    mfa_enabled: bool = False
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None


class UserListResponse(BaseModel):
    total: int
    page: int
    size: int
    results: List[UserOut]


class DeleteUserResponse(BaseModel):
    id: str
    deleted: bool
