"""
Models Pydantic â€” idx-roles
Responsable : Chef de Projet & SÃ©curitÃ©
"""

from typing import Optional, List
from pydantic import BaseModel


class RolePermissions(BaseModel):
    logs: List[str] = []
    alerts: List[str] = []
    incidents: List[str] = []
    users: List[str] = []
    rules: List[str] = []
    reports: List[str] = []
    audit: List[str] = []
    sources: List[str] = []
    retention: List[str] = []


class RoleModel(BaseModel):
    id: Optional[str] = None
    nom: str  # lecteur / analyste / administrateur
    permissions: RolePermissions
    description: Optional[str] = None
