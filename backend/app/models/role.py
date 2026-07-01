"""
Models Pydantic — idx-roles
Responsable : Chef de Projet & Sécurité
"""

from typing import Optional, List
from pydantic import BaseModel


class RolePermissions(BaseModel):
    # Chaque champ liste les actions autorisées pour une ressource donnée
    # (ex: logs=["read", "search"]). Représentation "document" stockée dans
    # Elasticsearch (index idx-roles), distincte de la matrice statique de core/rbac.py.
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
    id: Optional[str] = None       # identifiant du document Elasticsearch (None avant création)
    nom: str  # lecteur / analyste / administrateur
    permissions: RolePermissions
    description: Optional[str] = None
