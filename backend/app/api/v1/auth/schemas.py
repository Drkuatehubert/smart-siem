"""
schemas.py — Schémas Pydantic pour l'authentification
Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01, NFR-SEC-03
"""

from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)

    class Config:
        json_schema_extra = {
            "example": {
                "username": "analyste01",
                "password": "MonMotDePasse123!"
            }
        }


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # secondes


class UserProfile(BaseModel):
    user_id: str
    username: str
    email: Optional[str] = None
    role: str
    org_scope: Optional[str] = None
    is_active: bool


class TokenWithProfile(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserProfile
