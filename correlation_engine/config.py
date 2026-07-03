"""
correlation_engine/config.py
────────────────────────────
Rôle unique : centraliser TOUTES les constantes de configuration.
Aucune logique métier ici. Tout le reste importe depuis ce fichier.

Modifier une valeur ici = elle change dans tout le système.
"""
import os
from pathlib import Path

# ── Elasticsearch ─────────────────────────────────────────────────────────────
ES_HOST     = os.environ.get("ES_HOST",     "https://elasticsearch:9200")
ES_USER     = os.environ.get("ES_USER",     "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "")
ES_VERIFY_CERTS = os.environ.get("ES_VERIFY_CERTS", "true").lower() != "false"

# Chemin du certificat CA : résolu par rapport à ce module (et non au cwd du
# process qui démarre le worker) pour rester correct quel que soit l'endroit
# d'où "python -m correlation_engine.engine" est lancé.
_ca_cert_env = os.environ.get("ES_CACERT", "http_ca.crt")
_ca_cert_path = Path(_ca_cert_env)
if not _ca_cert_path.is_absolute():
    _resolved = Path(__file__).resolve().parent / _ca_cert_path
    _ca_cert_path = _resolved if _resolved.exists() else _ca_cert_path
ES_CACERT = str(_ca_cert_path)

# Index unique où le normalizer-api ("COLLECTE & NORMALISATION/normalizer-api")
# écrit les logs normalisés (voir envoyer_vers_es() dans app.py). Ne pas
# confondre avec un pattern d'index mensuel : il n'y en a qu'un seul ici.
ES_INDEX    = os.environ.get("ES_INDEX", "idx-logs")

# ── PostgreSQL ────────────────────────────────────────────────────────────────
PG_DSN = os.environ.get(
    "PG_DSN",
    "postgresql://postgres:postgres@postgres:5432/smartsiem",
)

# ── Notification API (backend) ─────────────────────────────────────────────────
# Endpoint interne appelé (best-effort, non bloquant) après chaque nouvelle
# alerte pour déclencher playbooks/notifications côté backend. Doit pointer
# vers le nom du service Docker Compose, pas "localhost" (conteneurs séparés).
API_NOTIFY_URL = os.environ.get(
    "API_NOTIFY_URL", "http://backend:8000/internal/alert-triggered"
)

# ── Timing du worker ──────────────────────────────────────────────────────────
# Intervalle entre deux cycles d'évaluation (secondes)
WORKER_INTERVAL_SEC = int(os.environ.get("WORKER_INTERVAL_SEC", "10"))

# Toutes les N secondes, recharger les règles depuis PG
# (permet de modifier une règle sans redémarrer le worker)
RULES_RELOAD_INTERVAL_SEC = int(os.environ.get("RULES_RELOAD_INTERVAL_SEC", "60"))

# Fenêtre de lookback globale pour les requêtes ES (secondes)
# Doit être >= à la plus grande fenêtre de règle
LOOKBACK_SEC = int(os.environ.get("LOOKBACK_SEC", "7200"))   # 2h — couvre les règles exfiltration (3600s) + buffer

# ── Déduplication des alertes ─────────────────────────────────────────────────
# Durée pendant laquelle une alerte identique est considérée comme doublon
DEDUP_WINDOW_SEC = int(os.environ.get("DEDUP_WINDOW_SEC", "300"))   # 5 minutes

# Taille max du cache de déduplication avant nettoyage
DEDUP_CACHE_MAX = int(os.environ.get("DEDUP_CACHE_MAX", "10000"))

# ── Convention des event_actions normalisés ───────────────────────────────────
# SOURCE UNIQUE DE VÉRITÉ pour tous les event_action du système.
# Le normalizer-api (extraire_action() dans app.py), les règles YAML, et ce
# moteur utilisent TOUS ces valeurs.
# Ajouter un nouveau type d'événement ici AVANT de l'utiliser ailleurs.
EVENT_ACTIONS = {
    # Authentification SSH
    "ssh_auth_failure": "Échec d'authentification SSH",
    "ssh_auth_success": "Succès d'authentification SSH",
    # Réseau
    "connection_blocked":        "Connexion bloquée par le firewall",
    "connection_allowed":        "Connexion autorisée",
    "large_outbound_transfer":   "Transfert de données volumineux sortant",
    "dns_query":                 "Requête DNS",
    "icmp_flood":                "Flood ICMP (tunnel probable)",
    # Système
    "file_read":                 "Accès fichier en lecture",
    "privilege_escalation":      "Escalade de privilèges détectée",
    "sudo_exec":                 "Exécution via sudo",
    "account_created":           "Création de compte",
    "service_created":           "Création de service",
    "process_started":           "Démarrage de processus",
    # Active Directory / Kerberos
    "kerberos_tgs_request":      "Demande de ticket Kerberos TGS",
    "kerberos_tgt_request":      "Demande de ticket Kerberos TGT",
    "admin_share_access":        "Accès à un partage administratif",
    # Web / application
    "http_post":                 "Requête HTTP POST",
    "http_exploit_attempt":      "Tentative d'exploit HTTP",
    "cloud_upload":              "Upload vers service cloud",
    "email_sent":                "Email envoyé",
    # WMI / PowerShell
    "wmi_exec":                  "Exécution distante WMI",
    "rdp_connection":            "Connexion RDP",
    "credential_dump":           "Dump de credentials",
    "smb_access":                "Accès SMB",
    "outbound_connection":       "Connexion sortante",
}
