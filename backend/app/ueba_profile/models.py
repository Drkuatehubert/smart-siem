from __future__ import annotations

from pydantic import BaseModel, Field


class UEBAProfile(BaseModel):
    # UEBA = User and Entity Behavior Analytics : profil comportemental d'un utilisateur,
    # avec un score de risque calculé à partir de ses activités passées (anomalies, écarts...).
    id: str
    username: str
    risk_score: int = Field(default=0)


class UEBAFilter(BaseModel):
    min_risk_score: int | None = None


class UEBARunRequest(BaseModel):
    scope: str | None = None  # périmètre sur lequel relancer le calcul (None = tout)
