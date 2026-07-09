"""app/core/audit.py — Utilitaire d'audit centralisé.

Re-exporte write_audit_log depuis auth/service pour usage dans tous les routeurs.
"""
from app.api.v1.auth.service import write_audit_log  # noqa: F401

__all__ = ["write_audit_log"]
