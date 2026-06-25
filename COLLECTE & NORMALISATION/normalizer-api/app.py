from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import uuid
import re
import uvicorn


import os

from elasticsearch import Elasticsearch
from datetime import datetime, timezone

_ES_HOST   = os.environ["ELASTICSEARCH_HOST"]
_ES_USER   = os.environ.get("ELASTICSEARCH_USERNAME", "elastic")
_ES_PASS   = os.environ["ELASTICSEARCH_PASSWORD"]
_ES_CA     = os.environ.get("ELASTICSEARCH_CA_CERTS") or None
_ES_VERIFY = os.environ.get("ELASTICSEARCH_TLS_VERIFY", "true").lower() != "false"

es = Elasticsearch(
    hosts=[_ES_HOST],
    basic_auth=(_ES_USER, _ES_PASS),
    ca_certs=_ES_CA,
    verify_certs=_ES_VERIFY,
)

app = FastAPI(title="Log Normalizer — Smart SIEM UCAC-ICAM")

# ============================================================================
# Schémas
# ============================================================================

class LogBrut(BaseModel):
    timestamp: str
    message: str
    host: str
    source: str = None
    log_type: str = None

class LogNormalise(BaseModel):
    id_es:            str
    horodatage:       str
    ip_source:        str
    ip_destination:   Optional[str]
    hote:             str
    type_log:         str
    severite:         str
    action_evenement: Optional[str]
    nom_utilisateur:  Optional[str]
    message_brut:     str
    tactique_mitre:   Optional[str]
    etiquettes:       Optional[str]

# ============================================================================
# Fonctions d'extraction
# ============================================================================

def deduire_severite(message: str) -> str:
    msg = message.lower()
    if any(k in msg for k in ["critical", "attack", "emergency", "emerg"]):
        return "critical"
    if any(k in msg for k in [
        "failed", "failure", "error", "denied", "invalid",
        "refused", "warning", "warn",
        "échec", "eventid 4625", "eventid 4740", "eventid 4726"
    ]):
        return "warning"
    return "info"

def deduire_type_log(message: str) -> str:
    msg = message.lower()

    # Auth — Linux + Windows
    if any(k in msg for k in [
        "password", "login", "logout", "authentication", "pam_unix", "pam(",
        "sudo", "su:", "sshd", "session opened", "session closed",
        "gdm", "keyring", "unlock",
        "eventid 4624", "eventid 4625", "eventid 4648",
        "eventid 4720", "eventid 4726", "eventid 4740", "eventid 4756",
        "connexion réussie", "échec de connexion",
        "compte utilisateur", "compte verrouillé"
    ]):
        return "auth"

    # Network
    if any(k in msg for k in [
        "networkmanager", "network", "dhcp", "interface",
        "firewall", "iptables", "port", "connection refused"
    ]):
        return "network"

    # System — Linux + Windows
    if any(k in msg for k in [
        "kernel", "systemd", "dbus", "service", "daemon",
        "started", "stopped", "cron",
        "eventid 7036", "eventid 4688", "eventid 1102",
        "processus créé", "service démarré", "journal audit"
    ]):
        return "system"

    return "application"

def extraire_ip_source(message: str, fallback: str) -> str:
    # Linux SSH : "from X.X.X.X"
    m = re.search(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})', message)
    if m:
        return m.group(1)
    # NetworkManager : "address=X.X.X.X"
    m = re.search(r'address=(\d{1,3}(?:\.\d{1,3}){3})', message)
    if m:
        return m.group(1)
    # Windows Event Log : "::1" ou IP dans les StringInserts
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})(?:\s*\|\s*\d+\s*\|\s*\d+)?$', message)
    if m and m.group(1) not in ("0.0.0.0", "127.0.0.1"):
        return m.group(1)
    return fallback or "unknown"

def extraire_ip_destination(message: str) -> Optional[str]:
    # Pattern "to X.X.X.X"
    m = re.search(r'\bto\s+(\d{1,3}(?:\.\d{1,3}){3})', message)
    if m:
        return m.group(1)
    # Pattern "dst=X.X.X.X"
    m = re.search(r'dst=(\d{1,3}(?:\.\d{1,3}){3})', message)
    if m:
        return m.group(1)
    return None

def extraire_nom_utilisateur(message: str) -> Optional[str]:
    # Linux SSH : "for [invalid user] USERNAME from"
    m = re.search(r'for\s+(?:invalid\s+user\s+)?(\w+)\s+from', message, re.IGNORECASE)
    if m:
        return m.group(1)
    # Linux pam : "for user USERNAME"
    m = re.search(r'for\s+user\s+(\w+)', message, re.IGNORECASE)
    if m:
        return m.group(1)
    # Linux sudo : "sudo: USERNAME :"
    m = re.search(r'sudo:\s+(\w+)\s+:', message, re.IGNORECASE)
    if m:
        return m.group(1)
    # Windows EventLog : "S-1-0-0 | USERNAME | HOSTNAME"
    m = re.search(r'S-1-0-0\s*\|\s*(\w[\w\s]*?)\s*\|', message)
    if m:
        username = m.group(1).strip()
        if username and username != "-":
            return username
    # Windows EventLog : "| USERNAME | DESKTOP-" (format StringInserts)
    m = re.search(r'\|\s*([A-Za-z][\w\s\-\.]+?)\s*\|\s*DESKTOP-', message)
    if m:
        username = m.group(1).strip()
        if username and len(username) > 1:
            return username
    return None

def extraire_action(message: str) -> Optional[str]:
    msg = message.lower()

    # Linux
    if "invalid user" in msg:
        return "invalid_user"
    if "failed password" in msg or "authentication failure" in msg:
        return "login_failed"
    if "accepted password" in msg or "accepted publickey" in msg:
        return "login_success"
    if "session opened" in msg:
        return "session_opened"
    if "session closed" in msg:
        return "session_closed"
    if "sudo" in msg and "command" in msg:
        return "privilege_escalation"
    if "connection refused" in msg:
        return "connection_refused"
    if "new lease" in msg or "dhcp" in msg:
        return "dhcp_lease"

    # Windows EventIDs
    if "eventid 4625" in msg or "échec de connexion" in msg:
        return "login_failed"
    if "eventid 4624" in msg or "connexion réussie" in msg:
        return "login_success"
    if "eventid 4648" in msg:
        return "privilege_escalation"
    if "eventid 4740" in msg or "compte verrouillé" in msg:
        return "account_locked"
    if "eventid 4720" in msg or "compte utilisateur créé" in msg:
        return "account_created"
    if "eventid 4726" in msg or "compte utilisateur supprimé" in msg:
        return "account_deleted"
    if "eventid 4756" in msg:
        return "group_member_added"
    if "eventid 1102" in msg or "journal audit effacé" in msg:
        return "audit_log_cleared"
    if "eventid 4688" in msg or "processus créé" in msg:
        return "process_created"
    if "eventid 7036" in msg or "service démarré" in msg:
        return "service_started"

    # Linux system
    if re.search(r'\bstarted\b', msg):
        return "service_started"
    if re.search(r'\bstopped\b|\bdeactivated\b', msg):
        return "service_stopped"

    return None


# ============================================================================
# Fonctions d'envoi vers Elasticsearch
# ============================================================================

def envoyer_vers_es(log_normalise: dict):
    """Indexe le log normalisé dans Elasticsearch."""
    try:
        es.index(
            index="siem-logs-current",
            document={
                "@timestamp":   log_normalise["horodatage"],
                "raw_log_id":   log_normalise["id_es"],
                "source_ip":    log_normalise["ip_source"],
                "dest_ip":      log_normalise["ip_destination"],
                "host":         log_normalise["hote"],
                "log_type":     log_normalise["type_log"],
                "severity":     log_normalise["severite"],
                "event_action": log_normalise["action_evenement"],
                "username":     log_normalise["nom_utilisateur"],
                "raw_message":  log_normalise["message_brut"],
                "mitre_tactic": log_normalise["tactique_mitre"],
                "tags":         log_normalise["etiquettes"],
                "ingested_at":  datetime.now(timezone.utc).isoformat(),
            }
        )
        print(f"[ES] Log indexé avec succès", flush=True)
    except Exception as e:
        print(f"[ES ERREUR] {e}", flush=True)


# ============================================================================
# Normalisation principale
# ============================================================================

def normaliser(log: dict) -> dict:
    message = log.get("message", "")
    return {
        "id_es":            str(uuid.uuid4()),
        "horodatage":       log.get("timestamp"),
        "ip_source":        extraire_ip_source(message, log.get("source")),
        "ip_destination":   extraire_ip_destination(message),
        "hote":             log.get("host"),
        "type_log":         deduire_type_log(message),
        "severite":         deduire_severite(message),
        "action_evenement": extraire_action(message),
        "nom_utilisateur":  extraire_nom_utilisateur(message),
        "message_brut":     message,
        "tactique_mitre":   None,
        "etiquettes":       None,
    }

# ============================================================================
# Endpoints
# ============================================================================

@app.post("/normalize", response_model=LogNormalise)
def normalizer_endpoint(log: LogBrut):
    return normaliser(log.model_dump())

@app.post("/normalize/batch")
def normalizer_batch(logs: list[LogBrut]):
    resultats = []
    for log in logs:
        normalise = normaliser(log.model_dump())
        print(f"[NORMALISE] {normalise}", flush=True)
        envoyer_vers_es(normalise)    # ← envoyer vers ES
        resultats.append(normalise)
    return resultats

@app.get("/health")
def health():
    return {"status": "ok", "https": True}

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=443,
        ssl_keyfile="/app/certs/server.key",
        ssl_certfile="/app/certs/server.crt"
    )