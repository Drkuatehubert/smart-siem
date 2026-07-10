from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import uuid
import re
import json
import uvicorn

import os
import redis as redis_lib

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

_REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
_REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
_redis: redis_lib.Redis | None = None


def get_redis() -> redis_lib.Redis | None:
    global _redis
    try:
        if _redis is None:
            _redis = redis_lib.Redis(
                host=_REDIS_HOST, port=_REDIS_PORT, db=0,
                decode_responses=True, socket_timeout=2,
            )
        return _redis
    except Exception as exc:
        print(f"[REDIS INIT ERREUR] {exc}", flush=True)
        return None


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
    ip_source:        Optional[str]
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

def _is_filtered_ip(ip: str) -> bool:
    """Retourne True pour les IPs internes/APIPA qui ne doivent pas être indexées."""
    return (
        ip.startswith("169.254.") or
        ip in ("127.0.0.1", "127.0.1.1", "::1", "0.0.0.0")
    )

def extraire_ip_source(message: str, fallback: str) -> Optional[str]:
    # Linux SSH : "from X.X.X.X"
    m = re.search(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})', message)
    if m:
        ip = m.group(1)
        if not _is_filtered_ip(ip):
            return ip
    # NetworkManager : "address=X.X.X.X"
    m = re.search(r'address=(\d{1,3}(?:\.\d{1,3}){3})', message)
    if m:
        ip = m.group(1)
        if not _is_filtered_ip(ip):
            return ip
    # Windows Event Log : IP dans les StringInserts
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})(?:\s*\|\s*\d+\s*\|\s*\d+)?$', message)
    if m:
        ip = m.group(1)
        if not _is_filtered_ip(ip):
            return ip
    # Fallback (host source)
    if fallback and fallback != "unknown" and not _is_filtered_ip(fallback):
        return fallback
    return None

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

    # ── SSH / Auth ────────────────────────────────────────────────────────────
    if "invalid user" in msg:
        return "login_failed"
    if "failed password" in msg or "authentication failure" in msg:
        return "login_failed"
    if "accepted password" in msg or "accepted publickey" in msg:
        return "login_success"
    if "session opened" in msg:
        return "session_opened"
    if "session closed" in msg:
        return "session_closed"
    if "new lease" in msg or "dhcp" in msg:
        return "dhcp_lease"

    # ── Réseau ────────────────────────────────────────────────────────────────
    if "deny" in msg or "blocked" in msg or "connection refused" in msg:
        return "connection_blocked"
    if "connection allowed" in msg or "connection accepted" in msg:
        return "connection_allowed"
    if re.search(r'\bdns\b', msg):
        return "dns_query"
    if "icmp flood" in msg or "flood icmp" in msg:
        return "icmp_flood"
    if "bytes_out" in msg or re.search(r'transfert\s*>', msg):
        return "large_outbound_transfer"

    # ── Windows avancé (tester avant les EventIDs génériques) ────────────────
    if "lsass" in msg or "credential" in msg:
        return "credential_dump"
    if "wmi" in msg:
        return "wmi_exec"
    if "smb" in msg or r"\\pipe\\" in msg:
        return "smb_access"

    # ── Windows EventIDs ──────────────────────────────────────────────────────
    if "eventid 4625" in msg or "échec de connexion" in msg:
        code_match = re.search(r'0xc[0-9a-f]{7}', message, re.IGNORECASE)
        code = code_match.group(0).lower() if code_match else ""
        benign_codes = {"0xc0000072", "0xc000006e", "0xc0000234", "0xc0000193", "0xc0000070"}
        if code in benign_codes:
            return None
        return "windows_login_failed"
    if "eventid 4624" in msg or "connexion réussie" in msg:
        m = re.search(r'0x3e7\s*\|\s*(\d+)\s*\|', message)
        if m:
            logon_type = m.group(1)
            if logon_type == "10":
                return "rdp_connection"
            if logon_type == "3":
                return "login_success"
            if logon_type == "2":
                return "login_success"
            if logon_type == "5":
                return "login_success"
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
        return "process_started"
    if "eventid 7045" in msg or "service créé" in msg:
        return "service_created"
    if "eventid 7036" in msg or "service démarré" in msg:
        return "service_started"

    # ── Active Directory / Kerberos ───────────────────────────────────────────
    if "eventid 4769" in msg:
        return "kerberos_tgs_request"
    if "eventid 4768" in msg:
        return "kerberos_tgt_request"
    if "eventid 5140" in msg or re.search(r'\bshare\b', msg):
        return "admin_share_access"

    # ── Système Linux ─────────────────────────────────────────────────────────
    if "sudo" in msg and "command" in msg:
        return "sudo_exec"
    if re.search(r'\bstarted\b', msg):
        return "service_started"
    if re.search(r'\bstopped\b|\bdeactivated\b', msg):
        return "service_stopped"

    # ── Web / Cloud ───────────────────────────────────────────────────────────
    if ("post" in msg and "401" in msg) or "exploit" in msg:
        return "http_exploit_attempt"
    if re.search(r'\bpost\b', msg):
        return "http_post"
    if "upload" in msg or "cloud" in msg:
        return "cloud_upload"

    return None


# ============================================================================
# Fonctions d'envoi vers Elasticsearch
# ============================================================================

def envoyer_vers_es(log_normalise: dict):
    """Indexe le log normalisé dans Elasticsearch."""
    try:
        mois_courant = datetime.now(timezone.utc).strftime("%Y.%m")
        index_name = f"siem-logs-{mois_courant}"
        es.index(
            index=index_name,
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
# Stockage Redis (fallback ES + statut agents)
# ============================================================================

def _detect_os(host: str) -> str:
    h = (host or "").lower()
    if "128" in h or "ubuntu" in h or "linux" in h:
        return "Ubuntu"
    if "129" in h or "windows" in h or "desktop" in h or "win" in h:
        return "Windows"
    return "Linux"


def stocker_dans_redis(log_normalise: dict, logs_count: int = 1) -> None:
    """Pousse le log dans recent_logs et met à jour le heartbeat agent:*."""
    try:
        r = get_redis()
        if r is None:
            return

        host = log_normalise.get("hote") or "unknown"
        ip   = log_normalise.get("ip_source") or "unknown"

        # Log récent au format ES — fallback quand ES est hors ligne
        log_es = {
            "@timestamp":   log_normalise.get("horodatage"),
            "source_ip":    log_normalise.get("ip_source"),
            "host":         log_normalise.get("hote"),
            "event_action": log_normalise.get("action_evenement"),
            "severity":     log_normalise.get("severite"),
            "raw_message":  log_normalise.get("message_brut"),
            "username":     log_normalise.get("nom_utilisateur"),
        }
        r.lpush("recent_logs", json.dumps(log_es, ensure_ascii=False))
        r.ltrim("recent_logs", 0, 499)

        # Heartbeat agent (expire automatiquement en 5 min)
        r.set(
            f"agent:{host}",
            json.dumps({
                "host":       host,
                "ip":         ip,
                "last_seen":  datetime.now(timezone.utc).isoformat(),
                "os":         _detect_os(host),
                "logs_count": logs_count,
            }),
            ex=300,
        )
    except Exception as exc:
        print(f"[REDIS ERREUR] {exc}", flush=True)


# ============================================================================
# Endpoints
# ============================================================================

@app.post("/normalize", response_model=LogNormalise)
def normalizer_endpoint(log: LogBrut):
    normalise = normaliser(log.model_dump())
    envoyer_vers_es(normalise)
    stocker_dans_redis(normalise, 1)
    print(f"[NORMALISE] action={normalise.get('action_evenement')} ip={normalise.get('ip_source')}", flush=True)
    return normalise

@app.post("/normalize/batch")
def normalizer_batch(logs: list[LogBrut]):
    resultats = []
    host_counts: dict[str, int] = {}
    for log in logs:
        normalise = normaliser(log.model_dump())
        envoyer_vers_es(normalise)
        host = normalise.get("hote") or "unknown"
        host_counts[host] = host_counts.get(host, 0) + 1
        stocker_dans_redis(normalise, host_counts[host])
        print(f"[NORMALISE] action={normalise.get('action_evenement')} host={host}", flush=True)
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