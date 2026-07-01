# Ré-exporte le router pour un import simplifié : `from app.incidents import router`.
from app.incidents.controller import router

__all__ = ["router"]
