"""
Models Pydantic — idx-users
Responsable : Chef de Projet & Sécurité
"""

from typing import Optional
from pydantic import BaseModel, EmailStr


class UserModel(BaseModel):
    # Représente un document utilisateur tel que stocké dans l'index Elasticsearch "idx-users".
    id: Optional[str] = None           # identifiant du document ES (None avant création)
    username: str
    password_hash: str                  # jamais le mot de passe en clair : uniquement le hash bcrypt (voir core/security.py)
    email: Optional[str] = None
    role_id: str  # Référence logique → idx-roles
    org_scope: Optional[str] = None  # équipe / service / filiale (RF-SEC-04, isolation multi-tenant)
    is_active: bool = True              # permet de désactiver un compte sans le supprimer
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None
