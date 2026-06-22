"""parser.py — Parsing RFC 3164/5424"""
import re
def parse_rfc3164(msg: str) -> dict:
    m=re.match(r"^<(\d+)>(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+):\s+(.+)$",msg)
    if not m: return {"raw_message":msg}
    return {"priority":m.group(1),"timestamp":m.group(2),"host":m.group(3),"process":m.group(4),"message":m.group(5),"raw_message":msg}

