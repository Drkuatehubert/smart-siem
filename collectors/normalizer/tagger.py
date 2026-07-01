"""Tagging de severite et de type pour les logs entrants."""

from __future__ import annotations

from typing import Dict


def tag_log(log: Dict[str, str]) -> Dict[str, str]:
    """Ajoute `severity` et `log_type` a partir du message brut."""
    raw = (log.get("raw_message") or "").lower()
    enriched = dict(log)

    if any(token in raw for token in ("critical", "ransom", "exfil", "root compromise")):
        enriched["severity"] = "critical"
    elif any(token in raw for token in ("failed", "denied", "invalid", "warning")):
        enriched["severity"] = "warning"
    else:
        enriched["severity"] = enriched.get("severity", "info")

    if any(token in raw for token in ("sshd", "password", "publickey", "login", "auth")):
        enriched["log_type"] = "auth"
    elif any(token in raw for token in ("iptables", "firewall", "connection", "port")):
        enriched["log_type"] = "network"
    elif any(token in raw for token in ("powershell", "cmd.exe", "process", "edr")):
        enriched["log_type"] = "endpoint"
    else:
        enriched["log_type"] = enriched.get("log_type", "application")

    return enriched
