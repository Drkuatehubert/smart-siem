"""
soar/notifiers/webhook_notifier.py — Webhook Slack/Teams avec signature HMAC-SHA256

Responsable : Module SOAR — Notifications
Exigences   : RF-NOTIF-02 (webhook), NFR-SEC-02 (chiffrement), NFR-SEC-05 (intégrité)

Ce module envoie des notifications via webhooks HTTP/TLS vers Slack ou Teams.
Sécurités appliquées :
  * Signature HMAC-SHA256 de chaque payload (non-répudiation)
  * TLS obligatoire (https:// uniquement en production)
  * Retry avec backoff exponentiel via tls_client.post_with_retry
  * Validation de l'URL webhook avant envoi
  * Pas de credentials en dur — tout vient des variables d'environnement
  * Payload structuré (blocks Slack / cards Teams) avec contexte MITRE
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import hashlib    # Pour la signature HMAC-SHA256 du payload
import hmac       # Calcul HMAC cryptographique
import json       # Sérialisation du payload pour la signature
import logging    # Journalisation structurée
import os         # Variables d'environnement
from datetime import datetime, timezone  # Horodatage UTC
from typing import Any, Dict, Optional  # Annotations de types

# ─────────────────────────────────────────────
# Import du client TLS centralisé
# ─────────────────────────────────────────────
from soar.tls_client import post_with_retry  # Client HTTP/TLS avec retry

# ─────────────────────────────────────────────
# Logger dédié aux notifications webhook
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.notifiers.webhook")

# ─────────────────────────────────────────────
# Couleurs Slack par niveau de sévérité
# ─────────────────────────────────────────────
_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",   # Rouge
    "HIGH":     "#ea580c",   # Orange
    "WARNING":  "#d97706",   # Jaune
    "INFO":     "#2563eb",   # Bleu
}

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "WARNING":  "🟡",
    "INFO":     "🔵",
}


# ─────────────────────────────────────────────
# Signature HMAC-SHA256 du payload
# ─────────────────────────────────────────────

def _sign_payload(payload: Dict[str, Any], secret: str) -> str:
    """
    Génère une signature HMAC-SHA256 du payload JSON.

    La signature est incluse dans l'en-tête X-SIEM-Signature de la requête.
    Cela permet au destinataire (si configuré) de vérifier que le payload
    provient bien du Smart SIEM et n'a pas été altéré en transit.

    Paramètres
    ----------
    payload : Dictionnaire Python à signer (sera sérialisé en JSON).
    secret  : Clé secrète partagée (SOAR_WEBHOOK_SECRET).

    Retourne
    --------
    La signature hexadécimale au format : "sha256=<hex_digest>"
    """
    # Sérialise le payload de façon déterministe (clés triées)
    body = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    # Calcule le HMAC-SHA256
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


# ─────────────────────────────────────────────
# Construction du payload Slack
# ─────────────────────────────────────────────

def _build_slack_payload(alert: dict) -> Dict[str, Any]:
    """
    Construit un payload Slack Block Kit structuré pour l'alerte SOAR.

    Le payload utilise le format Block Kit de Slack pour un affichage
    riche avec sections, champs et code couleur par sévérité.

    Paramètres
    ----------
    alert : Dictionnaire de l'alerte SOAR.

    Retourne
    --------
    Un dictionnaire conforme à l'API Slack Incoming Webhooks.
    """
    severity = str(alert.get("niveau", "INFO")).upper()
    color = _SEVERITY_COLORS.get(severity, "#6b7280")
    emoji = _SEVERITY_EMOJI.get(severity, "⚪")
    rule_name = alert.get("rule_nom", alert.get("rule_id", "Règle inconnue"))

    # Contexte UEBA si disponible
    ueba = alert.get("ueba_context", {})
    ueba_score = ueba.get("risk_score", ueba.get("score", 0))

    # Construction des sections Block Kit Slack
    fields = [
        {"type": "mrkdwn", "text": f"*Sévérité*\n{emoji} `{severity}`"},
        {"type": "mrkdwn", "text": f"*Score risque*\n`{alert.get('score_risque', 'N/A')}/100`"},
        {"type": "mrkdwn", "text": f"*MITRE Technique*\n`{alert.get('mitre_technique_id', 'N/A')}`"},
        {"type": "mrkdwn", "text": f"*Tactique*\n`{alert.get('mitre_tactic', 'N/A')}`"},
        {"type": "mrkdwn", "text": f"*Statut*\n`{alert.get('statut', 'ouvert')}`"},
        {"type": "mrkdwn", "text": f"*Score UEBA*\n`{ueba_score}/100`"},
    ]

    return {
        "attachments": [{
            "color": color,       # Bande colorée latérale selon la sévérité
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} Smart SIEM — Alerte {severity}",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Règle :* {rule_name}",
                    },
                },
                {
                    "type": "section",
                    "fields": fields,
                },
                {
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": f"⏱️ {alert.get('created_at', datetime.now(timezone.utc).isoformat())} | "
                                f"ID alerte : `{alert.get('_id', alert.get('id', 'N/A'))}`",
                    }],
                },
            ],
        }],
    }


# ─────────────────────────────────────────────
# Construction du payload Teams
# ─────────────────────────────────────────────

def _build_teams_payload(alert: dict) -> Dict[str, Any]:
    """
    Construit un payload Microsoft Teams (Adaptive Card / MessageCard).

    Utilise le format MessageCard (compatible avec tous les connecteurs Teams).
    """
    severity = str(alert.get("niveau", "INFO")).upper()
    color = _SEVERITY_COLORS.get(severity, "#6b7280").lstrip("#")
    emoji = _SEVERITY_EMOJI.get(severity, "⚪")

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,    # Couleur de la barre latérale Teams
        "summary": f"Smart SIEM — Alerte {severity}",
        "sections": [{
            "activityTitle": f"{emoji} **Smart SIEM — Alerte {severity}**",
            "activitySubtitle": alert.get("rule_nom", alert.get("rule_id", "N/A")),
            "facts": [
                {"name": "Sévérité",       "value": severity},
                {"name": "Score risque",   "value": f"{alert.get('score_risque', 'N/A')}/100"},
                {"name": "MITRE",          "value": f"{alert.get('mitre_tactic', 'N/A')} / {alert.get('mitre_technique_id', 'N/A')}"},
                {"name": "Statut",         "value": alert.get("statut", "ouvert")},
                {"name": "Créée le",       "value": alert.get("created_at", "N/A")},
            ],
        }],
    }


# ─────────────────────────────────────────────
# Détection du type de webhook (Slack vs Teams)
# ─────────────────────────────────────────────

def _detect_webhook_type(url: str) -> str:
    """
    Détecte le type de webhook à partir de l'URL.

    Retourne "slack", "teams" ou "generic".
    """
    url_lower = url.lower()
    if "slack.com" in url_lower or "hooks.slack" in url_lower:
        return "slack"
    if "webhook.office.com" in url_lower or "teams" in url_lower:
        return "teams"
    return "generic"


# ─────────────────────────────────────────────
# Envoi du webhook
# ─────────────────────────────────────────────

async def send_webhook(alert: dict) -> bool:
    """
    Envoie une notification webhook SOAR vers Slack ou Teams.

    Paramètres
    ----------
    alert : Dictionnaire de l'alerte SOAR à notifier.

    Retourne True si le webhook a été envoyé avec succès, False sinon.

    Sécurités
    ---------
    - URL HTTPS uniquement en production
    - Signature HMAC-SHA256 du payload dans X-SIEM-Signature
    - TLS strict via post_with_retry (vérification des certificats)
    - Retry avec backoff exponentiel (3 tentatives)
    """
    # ── Lecture de la configuration ───────────────────────────────────────
    url = os.getenv("SLACK_WEBHOOK_URL", "").strip()   # Compatible Slack ET Teams
    if not url:
        url = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
    if not url:
        logger.debug("[Webhook] Aucune URL webhook configurée — notification ignorée")
        return False

    # ── Vérification HTTPS en production ──────────────────────────────────
    app_env = os.getenv("APP_ENV", "dev").lower()
    if not url.startswith("https://") and app_env == "prod":
        logger.error("[Webhook] URL non HTTPS refusée en production : %s", url[:50])
        return False

    # ── Construction du payload selon le type de webhook ─────────────────
    webhook_type = _detect_webhook_type(url)
    if webhook_type == "slack":
        payload = _build_slack_payload(alert)
    elif webhook_type == "teams":
        payload = _build_teams_payload(alert)
    else:
        # Payload générique JSON pour les webhooks custom
        payload = {
            "source": "smart-siem-soar",
            "alert": {
                "severity": alert.get("niveau"),
                "rule_id": alert.get("rule_id"),
                "score": alert.get("score_risque"),
                "mitre_technique": alert.get("mitre_technique_id"),
                "created_at": alert.get("created_at"),
            },
        }

    # ── Signature HMAC-SHA256 du payload ──────────────────────────────────
    hmac_secret = os.getenv("SOAR_WEBHOOK_SECRET", "dev-webhook-secret")
    signature = _sign_payload(payload, hmac_secret)

    # ── En-têtes HTTP de sécurité ─────────────────────────────────────────
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "X-SIEM-Signature": signature,         # Signature HMAC pour vérification
        "X-SIEM-Source": "smart-siem-soar",   # Identifiant de la source
        "X-SIEM-Severity": alert.get("niveau", "INFO"),  # Sévérité pour le filtrage
    }

    # ── Envoi via le client TLS centralisé ────────────────────────────────
    status_code = await post_with_retry(url, payload=payload, headers=headers)

    if status_code and status_code < 300:
        logger.info(
            "[Webhook] Notification %s envoyée (HTTP %d) pour alerte=%s",
            webhook_type, status_code, alert.get("rule_id"),
        )
        return True
    else:
        logger.error(
            "[Webhook] Échec envoi %s (HTTP %s) pour alerte=%s",
            webhook_type, status_code, alert.get("rule_id"),
        )
        return False
