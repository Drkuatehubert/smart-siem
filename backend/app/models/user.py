"""
Models Pydantic â€” idx-users
Responsable : Chef de Projet & SÃ©curitÃ©
"""

from typing import Optional
from pydantic import BaseModel, EmailStr


class UserModel(BaseModel):
    id: Optional[str] = None
    username: str
    password_hash: str
    email: Optional[str] = None
    role_id: str  # RÃ©fÃ©rence logique â†’ idx-roles
    org_scope: Optional[str] = None  # Ã©quipe / service / filiale (RF-SEC-04)
    is_active: bool = True
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None
