# Ré-exporte le router pour un import simplifié : `from app.reports import router`.
from app.reports.controller import router

__all__ = ["router"]
