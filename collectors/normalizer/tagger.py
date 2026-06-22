"""tagger.py — Tagging automatique criticité + catégorie (RF-COL-04)"""
import re

SEVERITY_KEYWORDS = {
    "critical": ["critical","fatal","emergency","crit","alert"],
    "warning":  ["warning","warn","error","err","fail","denied","refused"],
    "info":     ["info","notice","debug","success","accepted"],
}
TYPE_PATTERNS = {
    "auth":        [r"ssh|sshd|login|logout|pam|sudo|auth|authentication|password"],
    "reseau":      [r"firewall|iptables|nftables|cisco|netflow|tcp|udp|icmp|port"],
    "application": [r"apache|nginx|http|https|django|flask|api|web"],
    "systeme":     [r"kernel|systemd|cron|disk|cpu|memory|process"],
}

def tag_log(data: dict) -> dict:
    msg = (data.get("raw_message") or "").lower()
    # Criticité
    severity = data.get("severity", "info")
    if not severity or severity not in ("info","warning","critical"):
        for level, keywords in SEVERITY_KEYWORDS.items():
            if any(k in msg for k in keywords):
                severity = level; break
        else:
            severity = "info"
    # Type
    log_type = data.get("log_type", "systeme")
    if not log_type or log_type not in ("auth","reseau","systeme","application"):
        for t, patterns in TYPE_PATTERNS.items():
            if any(re.search(p, msg) for p in patterns):
                log_type = t; break
        else:
            log_type = "systeme"
    return {**data, "severity": severity, "log_type": log_type,
            "tags": data.get("tags", []) + [severity, log_type]}
