# Ré-exporte le router pour un import simplifié : `from app.alerts import router`.
from app.alerts.controller import router

__all__ = ["router"]
