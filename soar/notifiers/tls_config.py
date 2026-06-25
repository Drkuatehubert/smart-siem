"""
soar/notifiers/tls_config.py — Configuration TLS centralisée pour les notificateurs

Responsable : Module Notifications & Sécurité des Communications
Exigences   : NFR-SEC-02 (chiffrement en transit), NFR-SEC-05 (TLS obligatoire)

Ce module centralise la création de contextes SSL/TLS durcis pour les protocoles
de notification (SMTP STARTTLS et requêtes HTTP/HTTPS).
"""

from __future__ import annotations

import logging
import os
import ssl
from pathlib import Path
from typing import Optional

from soar.tls_client import build_ssl_context

logger = logging.getLogger("soar.notifiers.tls_config")


def get_smtp_ssl_context(ca_bundle: Optional[str] = None) -> ssl.SSLContext:
    """
    Crée un contexte SSL/TLS sécurisé et durci pour le protocole SMTP (STARTTLS).
    Interdit les versions TLS inférieures à 1.2 et configure des suites de chiffrement fortes.
    """
    # Utilisation de build_ssl_context pour réutiliser la même logique stricte
    resolved_ca = ca_bundle or os.getenv("TLS_CA_BUNDLE")
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    
    if resolved_ca and Path(resolved_ca).exists():
        ctx.load_verify_locations(cafile=resolved_ca)
        logger.debug("[TLS SMTP] Bundle CA SMTP personnalisé chargé : %s", resolved_ca)
    else:
        ctx.load_default_certs()
        logger.debug("[TLS SMTP] Bundle CA SMTP système par défaut utilisé")
        
    return ctx


def get_http_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """
    Retourne un contexte SSL/TLS durci pour les communications HTTP (ex: Webhooks, Ticketing).
    Fait appel au module centralisé soar.tls_client.
    """
    return build_ssl_context(verify=verify)
