# Ré-exporte le router pour un import simplifié : `from app.audit_logs import router`.
from app.audit_logs.controller import router

__all__ = ["router"]
