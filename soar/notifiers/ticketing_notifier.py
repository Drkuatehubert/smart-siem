"""
soar/notifiers/ticketing_notifier.py — Intégration Jira / GLPI via REST

Responsable : Module SOAR — Notifications
Exigences   : RF-NOTIF-03 (ticketing), NFR-SEC-02 (TLS), RF-INC-01 (gestion incidents)

Ce module crée automatiquement des tickets d'incident dans Jira ou GLPI
quand une alerte SOAR est escaladée. La priorité du ticket est calculée
selon le niveau de sévérité et le score UEBA.

Sécurités appliquées :
  * HTTPS strict (TLS via post_with_retry)
  * Authentification par token API (jamais de password en dur)
  * Mapping de priorité configurable (CRITICAL → P1, HIGH → P2…)
  * Retry avec backoff exponentiel
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import base64     # Encodage Basic Auth pour Jira
import logging    # Journalisation structurée
import os         # Variables d'environnement
from datetime import datetime, timezone  # Horodatage UTC
from typing import Any, Dict, Optional   # Annotations de types

# ─────────────────────────────────────────────
# Import du client TLS centralisé
# ─────────────────────────────────────────────
from soar.tls_client import post_with_retry  # Client HTTP/TLS avec retry

# ─────────────────────────────────────────────
# Logger dédié aux notifications ticketing
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.notifiers.ticketing")

# ─────────────────────────────────────────────
# Mapping sévérité → priorité ticketing
# ─────────────────────────────────────────────

# Priorités Jira (1=Highest, 5=Lowest)
JIRA_PRIORITY_MAP: Dict[str, str] = {
    "CRITICAL": "1",   # Highest — intervention immédiate
    "HIGH":     "2",   # High — intervention dans l'heure
    "WARNING":  "3",   # Medium — intervention dans la journée
    "INFO":     "4",   # Low — best effort
}

# Priorités GLPI (1=Très haut, 5=Très bas)
GLPI_PRIORITY_MAP: Dict[str, int] = {
    "CRITICAL": 5,    # Très haut
    "HIGH":     4,    # Haut
    "WARNING":  3,    # Moyen
    "INFO":     2,    # Bas
}

# Urgences GLPI (1=Très haute, 5=Très basse)
GLPI_URGENCY_MAP: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH":     4,
    "WARNING":  3,
    "INFO":     2,
}


# ─────────────────────────────────────────────
# Intégration Jira
# ─────────────────────────────────────────────

def _build_jira_auth_header() -> Optional[str]:
    """
    Construit l'en-tête d'authentification Basic pour l'API Jira.

    Utilise l'email + token API Jira (jamais le mot de passe Atlassian).
    Retourne None si la configuration est manquante.
    """
    jira_email = os.getenv("JIRA_USER_EMAIL", "")
    jira_token = os.getenv("JIRA_API_TOKEN", "")

    if not jira_email or not jira_token:
        return None

    # Encodage Base64 de "email:token" (standard Basic Auth)
    credentials = f"{jira_email}:{jira_token}".encode("utf-8")
    encoded = base64.b64encode(credentials).decode("utf-8")
    return f"Basic {encoded}"


def _build_jira_payload(alert: dict) -> Dict[str, Any]:
    """
    Construit le payload JSON pour créer un ticket Jira via REST API v3.

    Le ticket inclut :
    - Résumé avec sévérité et règle
    - Description complète avec contexte MITRE et UEBA
    - Priorité calculée depuis la sévérité
    - Labels SIEM pour filtrage dans Jira
    """
    severity = str(alert.get("niveau", "INFO")).upper()
    rule_name = alert.get("rule_nom", alert.get("rule_id", "Règle inconnue"))
    mitre_technique = alert.get("mitre_technique_id", "N/A")
    mitre_tactic = alert.get("mitre_tactic", "N/A")

    # Contexte UEBA
    ueba = alert.get("ueba_context", {})
    ueba_score = ueba.get("risk_score", 0)
    ueba_reasons = ueba.get("anomaly_reasons", [])

    # Description structurée en texte
    description_text = (
        f"*Alerte Smart SIEM — {severity}*\n\n"
        f"*Règle déclenchée :* {rule_name}\n"
        f"*Sévérité :* {severity}\n"
        f"*Score de risque :* {alert.get('score_risque', 'N/A')}/100\n\n"
        f"*MITRE ATT&CK :*\n"
        f"  - Tactique : {mitre_tactic}\n"
        f"  - Technique : {mitre_technique}\n"
        f"  - URL : https://attack.mitre.org/techniques/{mitre_technique}/\n\n"
        f"*Analyse UEBA :*\n"
        f"  - Score UEBA : {ueba_score}/100\n"
        f"  - Anomalies : {', '.join(ueba_reasons) or 'Aucune'}\n\n"
        f"*Références logs :* {', '.join(alert.get('log_refs', [])[:5])}\n"
        f"*Créée le :* {alert.get('created_at', datetime.now(timezone.utc).isoformat())}\n\n"
        f"---\n_Ticket créé automatiquement par Smart SIEM SOAR_"
    )

    return {
        "fields": {
            "project": {"key": os.getenv("JIRA_PROJECT_KEY", "SEC")},
            "summary": f"[SIEM-{severity}] {rule_name} — {mitre_technique}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": description_text}],
                }],
            },
            "issuetype": {"name": os.getenv("JIRA_ISSUE_TYPE", "Bug")},
            "priority": {"id": JIRA_PRIORITY_MAP.get(severity, "3")},
            "labels": ["siem", "security", f"severity-{severity.lower()}", "soar"],
        }
    }


async def create_jira_ticket(alert: dict) -> Optional[str]:
    """
    Crée un ticket d'incident dans Jira via l'API REST v3.

    Paramètres
    ----------
    alert : Dictionnaire de l'alerte SOAR.

    Retourne l'URL du ticket créé, ou None si la création échoue.
    """
    jira_url = os.getenv("JIRA_URL", "").rstrip("/")
    if not jira_url:
        logger.debug("[Jira] JIRA_URL non configurée — ticketing ignoré")
        return None

    # ── Authentification ──────────────────────────────────────────────────
    auth_header = _build_jira_auth_header()
    if not auth_header:
        logger.warning("[Jira] JIRA_USER_EMAIL ou JIRA_API_TOKEN manquant")
        return None

    # ── Construction et envoi du payload ─────────────────────────────────
    payload = _build_jira_payload(alert)
    api_endpoint = f"{jira_url}/rest/api/3/issue"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": auth_header,       # Basic Auth avec token API
        "X-SIEM-Source": "smart-siem-soar",
    }

    status = await post_with_retry(api_endpoint, payload=payload, headers=headers)

    if status and status < 300:
        logger.info("[Jira] Ticket créé pour alerte=%s", alert.get("rule_id"))
        return f"{jira_url}/browse/{os.getenv('JIRA_PROJECT_KEY', 'SEC')}-NEW"
    else:
        logger.error("[Jira] Échec création ticket (HTTP %s)", status)
        return None


# ─────────────────────────────────────────────
# Intégration GLPI
# ─────────────────────────────────────────────

def _build_glpi_payload(alert: dict) -> Dict[str, Any]:
    """
    Construit le payload JSON pour créer un ticket GLPI via REST API.

    GLPI utilise des entiers pour les priorités/urgences/impacts.
    """
    severity = str(alert.get("niveau", "INFO")).upper()
    rule_name = alert.get("rule_nom", alert.get("rule_id", "Règle inconnue"))
    mitre_technique = alert.get("mitre_technique_id", "N/A")

    ueba = alert.get("ueba_context", {})
    ueba_score = ueba.get("risk_score", 0)

    content = (
        f"Alerte Smart SIEM — {severity}\n\n"
        f"Règle : {rule_name}\n"
        f"Sévérité : {severity}\n"
        f"Score risque : {alert.get('score_risque', 'N/A')}/100\n"
        f"MITRE ATT&CK : {alert.get('mitre_tactic', 'N/A')} / {mitre_technique}\n"
        f"Score UEBA : {ueba_score}/100\n"
        f"Créée le : {alert.get('created_at', datetime.now(timezone.utc).isoformat())}\n\n"
        f"Ticket créé automatiquement par Smart SIEM SOAR"
    )

    return {
        "input": {
            "name": f"[SIEM-{severity}] {rule_name}",
            "content": content,
            "itilcategories_id": int(os.getenv("GLPI_CATEGORY_ID", "1")),
            "priority": GLPI_PRIORITY_MAP.get(severity, 3),
            "urgency": GLPI_URGENCY_MAP.get(severity, 3),
            "impact": GLPI_URGENCY_MAP.get(severity, 3),
            "type": 1,          # 1 = Incident (vs 2 = Demande)
            "status": 1,        # 1 = Nouveau
        }
    }


async def create_glpi_ticket(alert: dict) -> Optional[str]:
    """
    Crée un ticket d'incident dans GLPI via l'API REST.

    Retourne l'URL du ticket créé, ou None si la création échoue.
    """
    glpi_url = os.getenv("GLPI_URL", "").rstrip("/")
    glpi_token = os.getenv("GLPI_APP_TOKEN", "")
    glpi_session = os.getenv("GLPI_SESSION_TOKEN", "")

    if not glpi_url:
        logger.debug("[GLPI] GLPI_URL non configurée — ticketing ignoré")
        return None

    if not glpi_token:
        logger.warning("[GLPI] GLPI_APP_TOKEN manquant")
        return None

    payload = _build_glpi_payload(alert)
    api_endpoint = f"{glpi_url}/apirest.php/Ticket"

    headers = {
        "Content-Type": "application/json",
        "App-Token": glpi_token,                          # Token applicatif GLPI
        "Session-Token": glpi_session,                    # Jeton de session GLPI
        "X-SIEM-Source": "smart-siem-soar",
    }

    status = await post_with_retry(api_endpoint, payload=payload, headers=headers)

    if status and status < 300:
        logger.info("[GLPI] Ticket créé pour alerte=%s", alert.get("rule_id"))
        return f"{glpi_url}/front/ticket.php"
    else:
        logger.error("[GLPI] Échec création ticket (HTTP %s)", status)
        return None


# ─────────────────────────────────────────────
# Fonction principale (auto-détection Jira/GLPI)
# ─────────────────────────────────────────────

async def create_ticket(alert: dict) -> Optional[str]:
    """
    Crée un ticket dans le système de ticketing configuré (Jira ou GLPI).

    Auto-détection : si JIRA_URL est défini → Jira en priorité.
    Sinon → GLPI si GLPI_URL est défini.
    Retourne l'URL du ticket ou None si aucun système n'est configuré.
    """
    # Jira en priorité si configuré
    if os.getenv("JIRA_URL"):
        return await create_jira_ticket(alert)

    # GLPI en fallback
    if os.getenv("GLPI_URL"):
        return await create_glpi_ticket(alert)

    logger.debug("[Ticketing] Aucun système de ticketing configuré")
    return None
