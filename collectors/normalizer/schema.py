"""schema.py — Schéma JSON cible normalisé (6 champs obligatoires RF-COL-03)"""
from datetime import datetime, timezone, timedelta
import uuid

REQUIRED_FIELDS = ["timestamp","source_ip","host","log_type","severity","raw_message"]

def build_normalized_doc(data: dict, retention_days: int = 30) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "log_id": str(uuid.uuid4()),
        "source_id": data.get("source_id"),
        "timestamp": data.get("timestamp", now.isoformat()),
        "source_ip": data.get("source_ip", "inconnu"),
        "host": data.get("host", "inconnu"),
        "log_type": data.get("log_type", "systeme"),
        "severity": data.get("severity", "info"),
        "raw_message": data.get("raw_message", ""),
        "normalized_fields": data.get("normalized_fields", {}),
        "tags": data.get("tags", []),
        "is_flagged": False,
        "archived": False,
        "retention_expiry": (now + timedelta(days=retention_days)).isoformat(),
    }
