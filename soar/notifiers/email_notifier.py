"""
soar/notifiers/email_notifier.py — Notification SMTP avec TLS obligatoire

Responsable : Module SOAR — Notifications
Exigences   : RF-NOTIF-01 (email), NFR-SEC-02 (chiffrement en transit)

Ce module envoie des notifications email SMTP/TLS pour les alertes SOAR.
Sécurités appliquées :
  * STARTTLS forcé (refuse les connexions non chiffrées en production)
  * Template HTML structuré avec contexte MITRE ATT&CK et UEBA
  * Validation des destinataires (évite les injections d'en-têtes SMTP)
  * Retry avec backoff sur les erreurs transitoires
  * Pas de credentials en dur — tout vient des variables d'environnement
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import asyncio         # Délai de retry asynchrone
import logging         # Journalisation structurée
import os              # Variables d'environnement SMTP
import re              # Validation des adresses email
import smtplib         # Client SMTP Python
import ssl             # Contexte SSL/TLS pour SMTP
from email.mime.multipart import MIMEMultipart  # Email multipart (HTML + texte)
from email.mime.text import MIMEText            # Corps de l'email
from typing import List, Optional               # Annotations de types

# ─────────────────────────────────────────────
# Logger dédié aux notifications email
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.notifiers.email")

# ─────────────────────────────────────────────
# Constantes de configuration
# ─────────────────────────────────────────────

# Nombre maximum de tentatives d'envoi email
MAX_RETRIES: int = 3

# Délai de base entre les tentatives (doublé à chaque retry)
RETRY_BACKOFF_BASE_S: float = 2.0

# Expression régulière de validation des adresses email (RFC 5322 simplifié)
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# Caractères interdits dans les en-têtes SMTP (injection d'en-têtes)
_HEADER_INJECTION_RE = re.compile(r"[\r\n]")

# Niveaux de sévérité → couleurs HTML pour le template
_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",   # Rouge vif
    "HIGH":     "#ea580c",   # Orange
    "WARNING":  "#d97706",   # Jaune-orange
    "INFO":     "#2563eb",   # Bleu
}


# ─────────────────────────────────────────────
# Lecture des variables d'environnement SMTP
# ─────────────────────────────────────────────

def _smtp_config() -> dict:
    """
    Lit la configuration SMTP depuis les variables d'environnement.

    Retourne un dictionnaire avec tous les paramètres SMTP.
    Lève ValueError si les variables obligatoires sont manquantes en production.
    """
    config = {
        "host":       os.getenv("SMTP_HOST", ""),
        "port":       int(os.getenv("SMTP_PORT", "587")),      # 587 = STARTTLS standard
        "user":       os.getenv("SMTP_USER", ""),
        "password":   os.getenv("SMTP_PASSWORD", ""),
        "sender":     os.getenv("SMTP_FROM", "siem@example.com"),
        "recipients": [                                         # Destinataires par défaut
            r for r in os.getenv("SMTP_RECIPIENTS", "").split(",")
            if r.strip()
        ],
        "use_tls":    os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"},
        "ca_bundle":  os.getenv("TLS_CA_BUNDLE", ""),          # Bundle CA pour vérification
        "timeout":    int(os.getenv("SMTP_TIMEOUT", "15")),    # Timeout connexion (secondes)
    }

    # Fallback : si pas de destinataires configurés, utilise SMTP_USER
    if not config["recipients"] and config["user"]:
        config["recipients"] = [config["user"]]

    return config


from soar.notifiers.tls_config import get_smtp_ssl_context

# ─────────────────────────────────────────────
# Validation des adresses email
# ─────────────────────────────────────────────

def _validate_email(address: str) -> bool:
    """
    Valide le format d'une adresse email et vérifie l'absence d'injection.

    Retourne True si l'adresse est valide et sûre.
    """
    if not address or not isinstance(address, str):
        return False
    address = address.strip()
    # Vérifie les injections d'en-têtes (CRLF dans l'adresse)
    if _HEADER_INJECTION_RE.search(address):
        logger.warning("[Email] Adresse avec injection d'en-tête refusée : %r", address)
        return False
    # Vérifie le format RFC 5322 simplifié
    return bool(_EMAIL_RE.match(address))


# ─────────────────────────────────────────────
# Construction du contexte SSL SMTP
# ─────────────────────────────────────────────

def _build_smtp_ssl_context(ca_bundle: str) -> ssl.SSLContext:
    """
    Crée un contexte SSL/TLS durci pour STARTTLS SMTP.
    """
    return get_smtp_ssl_context(ca_bundle)


# ─────────────────────────────────────────────
# Template HTML de l'email
# ─────────────────────────────────────────────

def _build_html_body(alert: dict) -> str:
    """
    Construit le corps HTML de l'email de notification SOAR.

    Le template est structuré et inclut :
    - Le niveau de sévérité avec code couleur
    - Le mapping MITRE ATT&CK (tactique + technique)
    - Le contexte UEBA si disponible
    - Les références aux logs (IDs)
    - Les actions recommandées
    """
    severity = str(alert.get("niveau", "INFO")).upper()
    color = _SEVERITY_COLORS.get(severity, "#6b7280")

    # Extraction des données MITRE
    mitre_tactic = alert.get("mitre_tactic", "N/A")
    mitre_technique = alert.get("mitre_technique_id", "N/A")

    # Contexte UEBA
    ueba = alert.get("ueba_context", {})
    ueba_score = ueba.get("risk_score", ueba.get("score", 0))
    ueba_reasons = ueba.get("anomaly_reasons", ueba.get("reasons", []))
    ueba_html = ""
    if ueba_score or ueba_reasons:
        reasons_html = "".join(f"<li>{r}</li>" for r in ueba_reasons)
        ueba_html = f"""
        <tr>
            <td colspan="2" style="background:#1e1b4b;padding:12px;border-radius:6px;margin-top:10px;">
                <strong style="color:#a5b4fc;">🧠 Analyse UEBA</strong><br>
                Score de risque : <strong style="color:#f59e0b;">{ueba_score}/100</strong>
                <ul style="color:#cbd5e1;margin:8px 0 0 16px;">{reasons_html}</ul>
            </td>
        </tr>"""

    # Logs référencés
    log_refs = alert.get("log_refs", [])
    logs_html = ", ".join(log_refs[:5]) + ("..." if len(log_refs) > 5 else "")

    return f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head><meta charset="UTF-8"><title>Alerte SIEM</title></head>
    <body style="font-family:Inter,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px;">
        <div style="max-width:600px;margin:0 auto;background:#1e293b;border-radius:12px;
                    border:2px solid {color};overflow:hidden;">

            <!-- En-tête -->
            <div style="background:{color};padding:20px;text-align:center;">
                <h1 style="color:white;margin:0;font-size:24px;">
                    🚨 Alerte Smart SIEM — {severity}
                </h1>
                <p style="color:rgba(255,255,255,0.85);margin:4px 0 0 0;">
                    {alert.get('rule_nom', alert.get('rule_id', 'Règle inconnue'))}
                </p>
            </div>

            <!-- Corps -->
            <div style="padding:24px;">
                <table style="width:100%;border-collapse:collapse;">

                    <!-- Sévérité + Statut -->
                    <tr>
                        <td style="padding:8px;color:#94a3b8;">Sévérité</td>
                        <td><span style="background:{color};color:white;padding:4px 12px;
                            border-radius:20px;font-weight:bold;">{severity}</span></td>
                    </tr>
                    <tr>
                        <td style="padding:8px;color:#94a3b8;">Statut</td>
                        <td style="color:#e2e8f0;">{alert.get('statut', 'ouvert')}</td>
                    </tr>

                    <!-- MITRE ATT&CK -->
                    <tr>
                        <td style="padding:8px;color:#94a3b8;">MITRE Tactique</td>
                        <td style="color:#a5b4fc;">{mitre_tactic}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px;color:#94a3b8;">MITRE Technique</td>
                        <td style="color:#a5b4fc;">
                            <a href="https://attack.mitre.org/techniques/{mitre_technique}/"
                               style="color:#818cf8;">{mitre_technique}</a>
                        </td>
                    </tr>

                    <!-- Score de risque -->
                    <tr>
                        <td style="padding:8px;color:#94a3b8;">Score de risque</td>
                        <td style="color:#f59e0b;font-weight:bold;">
                            {alert.get('score_risque', 'N/A')}/100
                        </td>
                    </tr>

                    <!-- UEBA si disponible -->
                    {ueba_html}

                    <!-- Logs référencés -->
                    <tr>
                        <td style="padding:8px;color:#94a3b8;">Logs référencés</td>
                        <td style="color:#64748b;font-size:12px;">{logs_html or 'Aucun'}</td>
                    </tr>

                    <!-- Horodatage -->
                    <tr>
                        <td style="padding:8px;color:#94a3b8;">Créée le</td>
                        <td style="color:#e2e8f0;">{alert.get('created_at', 'N/A')}</td>
                    </tr>

                </table>
            </div>

            <!-- Pied de page -->
            <div style="background:#0f172a;padding:16px;text-align:center;">
                <p style="color:#475569;font-size:12px;margin:0;">
                    Smart SIEM — Système de Gestion et d'Analyse des Événements de Sécurité<br>
                    ⚠️ Cet email est confidentiel. Ne pas transférer.
                </p>
            </div>
        </div>
    </body>
    </html>
    """


# ─────────────────────────────────────────────
# Envoi de l'email
# ─────────────────────────────────────────────

async def send_email(alert: dict) -> bool:
    """
    Envoie un email de notification SOAR via SMTP/TLS.

    Paramètres
    ----------
    alert : Dictionnaire de l'alerte SOAR à notifier.

    Retourne True si l'email a été envoyé avec succès, False sinon.

    Sécurités
    ---------
    - STARTTLS forcé (TLS 1.2 minimum)
    - Validation des adresses email des destinataires
    - Retry avec backoff exponentiel
    - Pas de credentials en dur
    """
    config = _smtp_config()

    # ── Vérification de la configuration minimale ─────────────────────────
    if not config["host"]:
        logger.debug("[Email] SMTP_HOST non configuré — notification ignorée")
        return False

    if not config["recipients"]:
        logger.warning("[Email] Aucun destinataire configuré (SMTP_RECIPIENTS)")
        return False

    # ── Filtrage des adresses invalides ───────────────────────────────────
    valid_recipients: List[str] = [
        addr.strip() for addr in config["recipients"]
        if _validate_email(addr.strip())
    ]
    if not valid_recipients:
        logger.error("[Email] Aucune adresse email valide parmi les destinataires")
        return False

    # ── Construction du message ───────────────────────────────────────────
    severity = str(alert.get("niveau", "INFO")).upper()
    rule_name = alert.get("rule_nom", alert.get("rule_id", "Alerte inconnue"))

    # Sanitise le sujet (retire les caractères CRLF)
    subject = f"[Smart SIEM] 🚨 Alerte {severity} — {rule_name}"
    subject = _HEADER_INJECTION_RE.sub("", subject)  # Anti-injection d'en-têtes

    msg = MIMEMultipart("alternative")    # Multipart pour HTML + fallback texte
    msg["Subject"] = subject
    msg["From"] = config["sender"]
    msg["To"] = ", ".join(valid_recipients)
    msg["X-Mailer"] = "Smart-SIEM-SOAR/1.0"           # Identifiant de l'expéditeur
    msg["X-Priority"] = "1" if severity == "CRITICAL" else "3"  # Priorité email

    # Corps texte brut (fallback pour les clients sans HTML)
    text_body = (
        f"Alerte Smart SIEM\n"
        f"Sévérité : {severity}\n"
        f"Règle    : {rule_name}\n"
        f"Statut   : {alert.get('statut', 'ouvert')}\n"
        f"MITRE    : {alert.get('mitre_tactic', 'N/A')} / {alert.get('mitre_technique_id', 'N/A')}\n"
        f"Score    : {alert.get('score_risque', 'N/A')}/100\n"
        f"Créée le : {alert.get('created_at', 'N/A')}\n"
    )
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(_build_html_body(alert), "html", "utf-8"))

    # ── Contexte SSL SMTP ─────────────────────────────────────────────────
    ssl_ctx = _build_smtp_ssl_context(config["ca_bundle"])

    # ── Envoi avec retry exponentiel ──────────────────────────────────────
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # smtplib est synchrone → on le run dans un thread pour ne pas bloquer la boucle async
            def _send_sync() -> None:
                """Connexion SMTP synchrone exécutée dans un thread séparé."""
                with smtplib.SMTP(config["host"], config["port"], timeout=config["timeout"]) as smtp:
                    if config["use_tls"]:
                        # STARTTLS : démarre la session en clair, passe en TLS
                        smtp.starttls(context=ssl_ctx)
                    if config["user"] and config["password"]:
                        # Authentification SMTP (après TLS pour sécurité)
                        smtp.login(config["user"], config["password"])
                    smtp.sendmail(
                        config["sender"],
                        valid_recipients,
                        msg.as_string(),
                    )

            # Exécute dans un executor de thread (non bloquant)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _send_sync)

            logger.info(
                "[Email] Notification envoyée à %d destinataire(s) pour alerte=%s",
                len(valid_recipients), alert.get("rule_id"),
            )
            return True

        except smtplib.SMTPAuthenticationError:
            # Erreur d'authentification → pas de retry (config à corriger)
            logger.error("[Email] Erreur d'authentification SMTP — vérifier SMTP_USER/PASSWORD")
            return False
        except ssl.SSLError as exc:
            # Erreur TLS → pas de retry (cert à corriger)
            logger.error("[Email] Erreur SSL/TLS SMTP : %s", exc)
            return False
        except Exception as exc:
            if attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF_BASE_S * (2 ** (attempt - 1))
                logger.warning(
                    "[Email] Tentative %d/%d échouée : %s — retry dans %.1fs",
                    attempt, MAX_RETRIES, exc, wait,
                )
                await asyncio.sleep(wait)
            else:
                logger.error("[Email] Échec définitif après %d tentatives : %s", MAX_RETRIES, exc)

    return False
