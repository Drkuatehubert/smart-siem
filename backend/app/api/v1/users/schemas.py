"""
schemas.py â€” SchÃ©mas Pydantic pour la gestion des utilisateurs (durcis)

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : RF-SEC-02, RF-SEC-04

Durcissements par rapport Ã  la version initiale :
  * `role_id` est une `Literal[...]` â‡’ impossible de crÃ©er un utilisateur
    avec un rÃ´le non reconnu (anti privilege-escalation) ;
  * `password` a des bornes explicites et la politique `PASSWORD_*` est appliquÃ©e ;
  * nouveaux schÃ©mas `UserUpdate`, `SetActiveRequest` ;
  * `UserOut` n'expose jamais `password_hash` ni `password_history`.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.api.v1.auth.schemas import _validate_password_strength
from app.core.rbac import Role


class UserCreate(BaseModel):
    """CrÃ©ation d'un utilisateur (admin uniquement)."""
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9._-]+$")
    email: Optional[EmailStr] = None
    password: str = Field(..., min_length=1, max_length=4096)
    role_id: Literal["lecteur", "analyste", "administrateur", "auditeur"] = Role.LECTEUR
    org_scope: Optional[str] = Field(default=None, max_length=64)

    @field_validator("password")
    @classmethod
    def _check_strength(cls, v: str) -> str:
        return _validate_password_strength(v)


class UserUpdate(BaseModel):
    """Mise Ã  jour partielle (PATCH /users/{id}). Tous champs optionnels."""
    email: Optional[EmailStr] = None
    role_id: Optional[Literal["lecteur", "analyste", "administrateur", "auditeur"]] = None
    org_scope: Optional[str] = Field(default=None, max_length=64)
    is_active: Optional[bool] = None


class SetActiveRequest(BaseModel):
    is_active: bool


class UserOut(BaseModel):
    """Sortie publique â€” ne JAMAIS inclure password_hash."""
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
