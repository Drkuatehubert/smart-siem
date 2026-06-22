"""parser_engine.py — Dispatcher de parsing (Grok, Regex, JSON natif)"""
import json, re
from datetime import datetime, timezone

def parse_log(raw: dict) -> dict:
    """Tente de parser le log brut et extrait les champs utiles."""
    msg = raw.get("raw_message", "")
    result = dict(raw)
    # Si c'est du JSON natif
    if isinstance(msg, str) and msg.strip().startswith("{"):
        try:
            parsed = json.loads(msg)
            result["normalized_fields"] = parsed
            result.setdefault("host", parsed.get("host","inconnu"))
            result.setdefault("source_ip", parsed.get("source_ip","inconnu"))
            return result
        except json.JSONDecodeError:
            pass
    # Syslog RFC 3164 : <priority>timestamp host process: message
    syslog_re = re.compile(r"^<?\d*>?\s*(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+):\s+(.+)$")
    m = syslog_re.match(msg or "")
    if m:
        result.setdefault("host", m.group(2))
        result["normalized_fields"] = {"process": m.group(3), "message": m.group(4)}
    return result
