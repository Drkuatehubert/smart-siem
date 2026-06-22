"""
Models Pydantic — idx-users
Responsable : Chef de Projet & Sécurité
"""

from typing import Optional
from pydantic import BaseModel, EmailStr


class UserModel(BaseModel):
    id: Optional[str] = None
    username: str
    password_hash: str
    email: Optional[str] = None
    role_id: str  # Référence logique → idx-roles
    org_scope: Optional[str] = None  # équipe / service / filiale (RF-SEC-04)
    is_active: bool = True
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None
