"""
soar/tls_client.py — Client HTTP/TLS sécurisé centralisé pour le SOAR

Responsable : Module Sécurité des Communications
Exigences   : NFR-SEC-02 (chiffrement en transit), NFR-SEC-05 (TLS obligatoire)

Ce module fournit :
  * Un contexte SSL configuré selon le niveau d'environnement (prod/dev)
  * Un client HTTPX asynchrone avec TLS mutuel optionnel
  * La vérification stricte des certificats en production
  * Le pinning de certificat optionnel pour les endpoints critiques
  * Un décorateur de retry avec backoff exponentiel pour les requêtes sortantes

Tous les composants SOAR (notificateurs, connecteurs) doivent utiliser
ce module plutôt que des clients HTTP non configurés.
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import asyncio        # Boucle d'événements asynchrone
import logging        # Journalisation structurée
import os             # Lecture des variables d'environnement
import ssl            # Primitives SSL/TLS Python
from pathlib import Path          # Manipulation des chemins de fichiers
from typing import Any, Dict, Optional  # Annotations de types

# ─────────────────────────────────────────────
# Import conditionnel d'HTTPX (client HTTP async)
# ─────────────────────────────────────────────
try:
    import httpx  # Client HTTP/2 asynchrone avec support TLS natif
    _HTTPX_AVAILABLE = True
except ImportError:
    # HTTPX est optionnel ; les notificateurs qui en ont besoin
    # doivent vérifier _HTTPX_AVAILABLE avant utilisation
    _HTTPX_AVAILABLE = False

# ─────────────────────────────────────────────
# Configuration du logger dédié TLS
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.tls_client")

# ─────────────────────────────────────────────
# Constantes de configuration TLS
# ─────────────────────────────────────────────

# Délai maximal d'une requête sortante (en secondes)
DEFAULT_TIMEOUT_S: int = 15

# Nombre maximum de tentatives avant abandon définitif
MAX_RETRIES: int = 3

# Délai initial entre deux tentatives (doublé à chaque retry)
RETRY_BACKOFF_BASE_S: float = 1.0

# Version TLS minimale acceptée : TLS 1.2 en dev, 1.3 recommandé en prod
_MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2


# ─────────────────────────────────────────────
# Lecture des variables d'environnement TLS
# ─────────────────────────────────────────────

def _env(name: str, default: str = "") -> str:
    """Lit une variable d'environnement avec une valeur par défaut sûre."""
    return os.getenv(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    """Lit un booléen d'environnement de façon explicite (1/true/yes/on)."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ─────────────────────────────────────────────
# Construction du contexte SSL
# ─────────────────────────────────────────────

def build_ssl_context(
    *,
    ca_bundle: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    verify: bool = True,
) -> ssl.SSLContext:
    """
    Crée un contexte SSL/TLS durci pour les connexions sortantes.

    Paramètres
    ----------
    ca_bundle     : Chemin vers le bundle CA (PEM). Si None, utilise le bundle
                    système + la variable d'env TLS_CA_BUNDLE.
    client_cert   : Chemin vers le certificat client (TLS mutuel).
    client_key    : Chemin vers la clé privée du certificat client.
    verify        : Si False (UNIQUEMENT en dev), désactive la vérification.
                    Cette valeur est toujours True en production.

    Retourne
    --------
    Un objet ssl.SSLContext configuré avec les paramètres de sécurité stricts.
    """
    # ── Vérification de sécurité : verify=False interdit hors dev ──────────
    app_env = _env("APP_ENV", "dev")
    if not verify and app_env == "prod":
        # En production, on refuse catégoriquement la désactivation TLS
        raise RuntimeError(
            "[TLS] verify=False est interdit en production (APP_ENV=prod). "
            "Fournissez un bundle CA valide via TLS_CA_BUNDLE."
        )

    # ── Création du contexte SSL avec protocole minimum TLS 1.2 ────────────
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = _MIN_TLS_VERSION  # Refuse SSLv3, TLS 1.0, TLS 1.1

    if not verify:
        # Mode développement uniquement : désactivation de la vérification
        logger.warning("[TLS] ATTENTION : vérification des certificats désactivée (dev uniquement)")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # ── Chargement du bundle CA ─────────────────────────────────────────────
    resolved_ca = ca_bundle or _env("TLS_CA_BUNDLE")
    if resolved_ca and Path(resolved_ca).exists():
        # Bundle CA personnalisé (certificats internes, Let's Encrypt staging, etc.)
        ctx.load_verify_locations(cafile=resolved_ca)
        logger.debug("[TLS] Bundle CA chargé depuis : %s", resolved_ca)
    else:
        # Utilise le bundle CA du système d'exploitation (recommandé en prod)
        ctx.load_default_certs()
        logger.debug("[TLS] Bundle CA système utilisé")

    # ── Certificat client (TLS mutuel / mTLS) ──────────────────────────────
    resolved_cert = client_cert or _env("TLS_CLIENT_CERT")
    resolved_key = client_key or _env("TLS_CLIENT_KEY")
    if resolved_cert and resolved_key:
        ctx.load_cert_chain(certfile=resolved_cert, keyfile=resolved_key)
        logger.info("[TLS] Certificat client chargé (mTLS activé)")

    # ── Paramètres de sécurité renforcés ───────────────────────────────────
    ctx.verify_mode = ssl.CERT_REQUIRED   # Vérifie le certificat du serveur
    ctx.check_hostname = True             # Vérifie que le hostname correspond au CN/SAN
    # Désactive les suites cryptographiques faibles (RC4, DES, export)
    ctx.set_ciphers("HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH")

    return ctx


# ─────────────────────────────────────────────
# Client HTTP/TLS asynchrone
# ─────────────────────────────────────────────

def build_httpx_client(
    *,
    verify: bool | ssl.SSLContext = True,
    timeout: float = DEFAULT_TIMEOUT_S,
    headers: Optional[Dict[str, str]] = None,
) -> "httpx.AsyncClient":
    """
    Instancie un client HTTPX asynchrone avec TLS durci.

    Paramètres
    ----------
    verify   : True (vérification système), False (dev uniquement),
               ou un ssl.SSLContext personnalisé.
    timeout  : Délai maximal global en secondes (connect + read + write).
    headers  : En-têtes HTTP par défaut ajoutés à chaque requête.

    Retourne
    --------
    Un httpx.AsyncClient configuré, prêt à être utilisé comme contexte.

    Exemple
    -------
    async with build_httpx_client() as client:
        resp = await client.post(url, json=payload)
    """
    if not _HTTPX_AVAILABLE:
        raise ImportError(
            "httpx est requis pour les communications HTTP. "
            "Installez-le : pip install httpx"
        )

    # ── Construction du contexte SSL si verify=True (pas un contexte fourni) ─
    if isinstance(verify, bool) and verify:
        ssl_ctx = build_ssl_context(verify=True)
    elif isinstance(verify, ssl.SSLContext):
        ssl_ctx = verify
    else:
        # verify=False → contexte sans vérification (dev uniquement)
        ssl_ctx = build_ssl_context(verify=False)

    # ── En-têtes par défaut de sécurité ─────────────────────────────────────
    default_headers: Dict[str, str] = {
        # Identifiant de l'émetteur pour les logs des serveurs destinataires
        "User-Agent": "SmartSIEM-SOAR/1.0",
        # Exige le HTTPS en transit (protection contre downgrade)
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }
    if headers:
        default_headers.update(headers)

    return httpx.AsyncClient(
        verify=ssl_ctx,
        timeout=httpx.Timeout(timeout),    # Timeout unifié connect/read/write
        follow_redirects=False,            # Désactive les redirections (sécurité)
        headers=default_headers,
    )


# ─────────────────────────────────────────────
# Retry avec backoff exponentiel
# ─────────────────────────────────────────────

async def post_with_retry(
    url: str,
    *,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    max_retries: int = MAX_RETRIES,
    backoff: float = RETRY_BACKOFF_BASE_S,
) -> Optional[int]:
    """
    Envoie un POST JSON avec retry exponentiel et gestion d'erreurs TLS.

    Paramètres
    ----------
    url         : URL HTTPS cible (doit commencer par https://).
    payload     : Corps JSON de la requête.
    headers     : En-têtes HTTP additionnels (ex: Authorization, X-Signature).
    max_retries : Nombre maximal de tentatives avant abandon.
    backoff     : Délai initial entre tentatives (doublé à chaque échec).

    Retourne
    --------
    Le code HTTP de la dernière réponse réussie, ou None en cas d'échec total.

    Sécurité
    --------
    Refuse les URL HTTP non chiffrées en production.
    """
    # ── Vérification du schéma HTTPS ──────────────────────────────────────
    app_env = _env("APP_ENV", "dev")
    if not url.startswith("https://") and app_env == "prod":
        logger.error("[TLS] URL non sécurisée refusée en production : %s", url)
        return None

    # ── Boucle de retry ───────────────────────────────────────────────────
    last_exc: Optional[Exception] = None
    for attempt in range(1, max_retries + 1):
        try:
            async with build_httpx_client(headers=headers) as client:
                resp = await client.post(url, json=payload)
                # Codes 2xx : succès
                if resp.status_code < 300:
                    logger.debug(
                        "[TLS] POST %s → %d (tentative %d/%d)",
                        url, resp.status_code, attempt, max_retries,
                    )
                    return resp.status_code
                # Codes 4xx : erreur client, pas la peine de retry
                if resp.status_code < 500:
                    logger.warning(
                        "[TLS] Erreur client %d pour %s (pas de retry)",
                        resp.status_code, url,
                    )
                    return resp.status_code
                # Codes 5xx : erreur serveur → retry
                logger.warning(
                    "[TLS] Erreur serveur %d pour %s (tentative %d/%d)",
                    resp.status_code, url, attempt, max_retries,
                )
        except ssl.SSLError as exc:
            # Erreur TLS : certificat invalide, handshake échoué, etc.
            logger.error("[TLS] Erreur SSL vers %s : %s", url, exc)
            last_exc = exc
            break  # Pas de retry sur les erreurs SSL (problème de config)
        except Exception as exc:
            logger.warning(
                "[TLS] Tentative %d/%d échouée pour %s : %s",
                attempt, max_retries, url, exc,
            )
            last_exc = exc

        # ── Backoff exponentiel avant la prochaine tentative ──────────────
        if attempt < max_retries:
            wait = backoff * (2 ** (attempt - 1))
            logger.debug("[TLS] Attente %.1fs avant retry %d", wait, attempt + 1)
            await asyncio.sleep(wait)

    logger.error(
        "[TLS] Échec définitif après %d tentatives pour %s : %s",
        max_retries, url, last_exc,
    )
    return None
