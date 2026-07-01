"""Construction du document normalise stocke dans Elasticsearch."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict


def build_normalized_doc(data: Dict[str, Any]) -> Dict[str, Any]:
    """Construit le JSON canonique exige par `SIEM Intelligent V1`."""
    now = datetime.now(timezone.utc)
    return {
        "log_id": data.get("log_id") or uuid.uuid4().hex,
        "timestamp": data.get("timestamp") or now.isoformat(),
        "host": data.get("host", "unknown"),
        "source_ip": data.get("source_ip", "0.0.0.0"),
        "log_type": data.get("log_type", "application"),
        "severity": data.get("severity", "info"),
        "raw_message": data.get("raw_message", ""),
        "normalized_fields": data.get("normalized_fields", {}),
        "tags": data.get("tags", []),
        "is_flagged": bool(data.get("is_flagged", False)),
        "archived": bool(data.get("archived", False)),
        "retention_expiry": data.get("retention_expiry") or (now + timedelta(days=30)).isoformat(),
    }
