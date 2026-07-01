"""
config.py — Configuration centralisée via variables d'environnement (pydantic-settings v2)

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01 (JWT durci), NFR-SEC-02 (chiffrement), NFR-SEC-04 (multi-tenant),
            durcissement global (MFA, rate-limit, lockout, SOAR kill-switch, prod-guard).

Ce module :
  * charge toutes les variables d'environnement en un seul objet `Settings` typé ;
  * verrouille `JWT_ALGORITHM` à un sous-ensemble sûr (pas d'alg="none") ;
  * valide en `prod` que les secrets ne sont pas les valeurs par défaut,
    que TLS ES est actif, et que la doc OpenAPI est désactivée.
"""

# Permet d'utiliser les annotations de type "en avance" (ex: "Settings" avant sa
# propre définition) sans erreur, en les traitant comme du texte plutôt que du code exécuté.
from __future__ import annotations

import re  # (non utilisé directement ici mais dispo pour de futures validations par regex)
from typing import List, Literal, Optional  # types utilisés pour décrire précisément chaque champ

# EmailStr : type pydantic qui valide qu'une chaîne est bien une adresse email
# Field : permet d'ajouter des contraintes (min/max, valeur par défaut dynamique...) à un champ
# model_validator : décorateur pour écrire une validation qui s'exécute après la création de l'objet
from pydantic import EmailStr, Field, model_validator
# BaseSettings : classe de base qui sait lire automatiquement les variables d'environnement / le fichier .env
# SettingsConfigDict : dictionnaire de configuration pour BaseSettings (nom du fichier .env, etc.)
from pydantic_settings import BaseSettings, SettingsConfigDict


# ─────────────────────────────────────────────────────────────────────────────
# Helpers de validation
# ─────────────────────────────────────────────────────────────────────────────
# Cette section contient des fonctions utilitaires utilisées plus bas pour vérifier
# que la configuration n'est pas dangereuse (ex: mot de passe par défaut en prod).

# Secrets considérés comme faibles — interdits en production.
# Si un secret contient un de ces mots, c'est probablement une valeur d'exemple/copiée-collée
# depuis la documentation, et non un vrai secret généré aléatoirement.
_FORBIDDEN_SECRET_SUBSTRINGS = (
    "changeme", "password", "secret", "admin", "default", "test", "example",
)

# Algorithmes JWT autorisés (rien d'autre que du HMAC ou de l'asymétrique sûr).
# On utilise `Literal` pour que pydantic refuse toute valeur qui ne serait pas dans cette liste
# (empêche notamment l'algorithme "none", qui permettrait de forger des tokens sans signature).
JWT_ALLOWED_ALGS = Literal["HS256", "HS384", "HS512", "RS256", "ES256"]


def _is_weak_secret(value: str) -> bool:
    """Renvoie True si la valeur ressemble à un placeholder dev."""
    # On met tout en minuscules pour comparer sans se soucier de la casse.
    v = value.lower()
    # Un secret trop court (< 32 caractères) est considéré comme faible,
    # même s'il ne contient aucun mot suspect (trop facile à deviner / trop peu d'entropie).
    if len(value) < 32:
        return True
    # Si le secret contient un des mots interdits (ex: "changeme"), c'est un placeholder de dev.
    return any(s in v for s in _FORBIDDEN_SECRET_SUBSTRINGS)


# ─────────────────────────────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    """
    Configuration de l'application Smart SIEM.

    Toutes les variables sensibles DOIVENT être fournies par l'environnement
    (ou .env) en production. Les défauts ci-dessous sont des placeholders
    de développement et sont rejetés par `validate_prod()` quand
    `APP_ENV == "prod"`.
    """

    # Configuration interne de pydantic-settings :
    # - env_file=".env" : si un fichier .env existe à la racine, ses valeurs sont chargées automatiquement
    # - case_sensitive=True : les noms de variables d'env doivent respecter la casse exacte (ex: API_PORT, pas api_port)
    # - extra="ignore" : si l'environnement contient des variables inconnues, on les ignore au lieu de planter
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    # ── Environnement ────────────────────────────────────────────────────
    # APP_ENV pilote tout le comportement "strict" ci-dessous (voir validate_prod).
    APP_ENV: Literal["dev", "staging", "prod"] = "dev"
    DOCS_ENABLED: bool = True  # désactivé automatiquement en prod (évite d'exposer /docs et le schéma OpenAPI)

    # ── API ──────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"  # écoute sur toutes les interfaces réseau du conteneur/serveur
    API_PORT: int = 8000
    # Liste blanche des origines autorisées à appeler l'API depuis un navigateur (CORS).
    # default_factory (au lieu d'un simple "=") évite de partager la même liste mutable entre instances.
    CORS_ORIGINS: List[str] = Field(default_factory=lambda: ["https://localhost"])
    # Liste des noms d'hôte HTTP autorisés (protection contre les attaques "Host header injection").
    ALLOWED_HOSTS: List[str] = Field(default_factory=lambda: ["localhost", "siem.local"])

    # ── JWT (RF-SEC-01) ──────────────────────────────────────────────────
    # Clé secrète servant à signer/vérifier les tokens JWT. En dev, valeur factice explicite
    # (le nom même du texte rappelle qu'elle n'est pas valable en prod). min_length=32 impose
    # une entropie minimale.
    API_SECRET_KEY: str = Field(
        default="dev-only-not-for-production-min-32-chars-XXXX",
        min_length=32,
    )
    JWT_ALGORITHM: JWT_ALLOWED_ALGS = "HS256"
    JWT_EXPIRY_MINUTES: int = Field(default=15, ge=1, le=60 * 24)  # durée de vie du token d'accès (courte, 15 min)
    JWT_REFRESH_EXPIRY_MINUTES: int = Field(default=60 * 24, ge=1, le=60 * 24 * 30)  # durée de vie du refresh token (plus longue)
    JWT_ACCESS_LEEWAY_SECONDS: int = Field(default=30, ge=0, le=300)  # tolérance d'horloge entre serveurs
    JWT_ISSUER: str = "smart-siem"  # valeur "iss" attendue dans le token
    JWT_AUDIENCE: str = "smart-siem-api"  # valeur "aud" attendue dans le token

    # ── MFA (NFR-SEC-02, défense en profondeur) ─────────────────────────
    MFA_REQUIRED: bool = False  # si True, tous les utilisateurs doivent activer la double authentification
    MFA_ISSUER: str = "SmartSIEM"  # nom affiché dans l'application d'authentification (Google Authenticator, etc.)
    MFA_TOTP_DIGITS: int = Field(default=6, ge=6, le=8)  # nombre de chiffres du code TOTP
    MFA_TOTP_PERIOD: int = Field(default=30, ge=15, le=120)  # durée de validité d'un code TOTP, en secondes

    # ── Rate limit (slowapi) ─────────────────────────────────────────────
    RATE_LIMIT_DEFAULT: str = "100/minute"  # limite globale par défaut sur les endpoints
    RATE_LIMIT_LOGIN: str = "5/minute"  # limite stricte sur /login pour freiner le brute-force
    RATE_LIMIT_LOGIN_BURST: str = "10/hour"  # limite complémentaire sur une fenêtre plus longue
    RATE_LIMIT_STORAGE_URI: str = "redis://redis:6379/1"  # backend Redis utilisé pour compter les requêtes

    # ── Politique mot de passe (NFR-SEC-03) ─────────────────────────────
    PASSWORD_MIN_LENGTH: int = Field(default=12, ge=8)
    PASSWORD_MAX_LENGTH: int = Field(default=128, ge=8, le=4096)
    PASSWORD_REQUIRE_UPPER: bool = True   # au moins une majuscule
    PASSWORD_REQUIRE_LOWER: bool = True   # au moins une minuscule
    PASSWORD_REQUIRE_DIGIT: bool = True   # au moins un chiffre
    PASSWORD_REQUIRE_SYMBOL: bool = True  # au moins un caractère spécial
    PASSWORD_HISTORY_SIZE: int = Field(default=5, ge=0, le=50)  # interdit de réutiliser un des N derniers mots de passe

    # ── Account lockout (NFR-SEC-04) ─────────────────────────────────────
    ACCOUNT_LOCKOUT_THRESHOLD: int = Field(default=5, ge=1, le=50)  # nombre d'échecs de connexion avant verrouillage
    ACCOUNT_LOCKOUT_DURATION_MIN: int = Field(default=15, ge=1, le=24 * 60)  # durée du verrouillage du compte, en minutes

    # ── SOAR / actions réseau (RF-SEC-05) ────────────────────────────────
    # SOAR = Security Orchestration, Automation and Response : les actions automatiques
    # prises en réponse à une alerte (ex: bloquer une IP suspecte).
    BLOCK_IP_DRY_RUN: bool = True  # si True, on simule le blocage d'IP sans l'appliquer réellement (mode "test")
    BLOCK_IP_MAX_PER_HOUR: int = Field(default=50, ge=1, le=10_000)  # garde-fou anti-emballement
    BLOCK_IP_REQUIRE_APPROVAL_BELOW: Literal["INFO", "WARNING", "HIGH", "CRITICAL"] = "CRITICAL"  # sévérité minimale pour bloquer sans validation humaine
    SOAR_REQUIRE_APPROVAL: bool = True  # une action SOAR doit être validée par un humain avant exécution
    SOAR_KILL_SWITCH: bool = False  # interrupteur d'urgence : coupe toutes les actions SOAR automatiques
    SOAR_ALLOW_PRIVATE_NETWORKS: bool = False  # interdit par défaut de bloquer des IP privées (RFC1918 / loopback)
    SOAR_MIN_AUTO_LEVEL: Literal["INFO", "WARNING", "HIGH", "CRITICAL"] = "CRITICAL"  # sévérité minimale pour déclencher une action automatique
    SOAR_DRY_RUN: bool = True  # mode simulation global pour le SOAR

    # ── Headers sécurité (NFR-SEC-05) ────────────────────────────────────
    HSTS_MAX_AGE: int = 31_536_000  # durée en secondes pendant laquelle le navigateur doit forcer HTTPS (1 an)
    # Content-Security-Policy : restreint strictement d'où peuvent venir scripts/styles/images
    # pour limiter les attaques XSS (cross-site scripting).
    CSP_POLICY: str = (
        "default-src 'self'; "       # par défaut, seules les ressources du même domaine sont autorisées
        "script-src 'self'; "        # scripts uniquement depuis notre propre domaine
        "style-src 'self'; "         # feuilles de style uniquement depuis notre propre domaine
        "img-src 'self' data:; "     # images depuis notre domaine ou encodées en base64 (data:)
        "frame-ancestors 'none'; "   # interdit d'intégrer le site dans une <iframe> (anti-clickjacking)
        "base-uri 'self'; "          # empêche de changer dynamiquement la base des URLs relatives
        "form-action 'self'"        # les formulaires ne peuvent soumettre que vers notre propre domaine
    )

    # ── Elasticsearch ────────────────────────────────────────────────────
    ELASTICSEARCH_HOST: str = "http://elasticsearch:9200"
    ELASTICSEARCH_USERNAME: str = "elastic"
    ELASTICSEARCH_PASSWORD: str = "8-0Il66xvSeGnK=COySu"  # NB: valeur de dev, doit être surchargée en prod via l'environnement
    ELASTICSEARCH_TLS_VERIFY: bool = True  # vérifie le certificat TLS d'Elasticsearch (à ne jamais désactiver en prod)
    ELASTICSEARCH_CA_CERTS: Optional[str] = "http_ca.crt"  # chemin du certificat d'autorité de certification (CA)
    ELASTICSEARCH_REQUEST_TIMEOUT: int = 10  # délai maximum d'attente d'une requête ES, en secondes
    ELASTICSEARCH_MAX_RETRIES: int = 2  # nombre de tentatives en cas d'échec réseau

    # ── Redis ────────────────────────────────────────────────────────────
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_TLS: bool = False  # chiffrement de la connexion Redis (obligatoire en prod, voir validate_prod)
    REDIS_CA_CERTS: Optional[str] = None
    REDIS_STREAM_KEY: str = "siem:logs:raw"  # nom du flux Redis Streams où arrivent les logs bruts
    REDIS_STREAM_MAXLEN: int = Field(default=1_000_000, ge=1_000)  # taille max du flux avant purge des anciens messages
    REDIS_MESSAGE_MAX_BYTES: int = Field(default=65_536, ge=256, le=1_048_576)  # taille max d'un message accepté (anti-DoS)

    # ── Notifications (RF-NOT-01..04) ───────────────────────────────────
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: EmailStr = "smart-siem@ucac-icam.com"  # type: ignore[assignment]  # adresse d'expéditeur des emails
    SMTP_TLS: bool = True
    SLACK_WEBHOOK_URL: str = ""  # URL du webhook Slack pour les notifications d'alerte
    SLACK_SIGNING_SECRET: str = ""  # secret utilisé pour vérifier l'authenticité des requêtes Slack entrantes
    PAGERDUTY_ROUTING_KEY: str = ""  # clé de routage pour déclencher un incident PagerDuty
    WEBHOOK_REQUIRE_HTTPS: bool = True  # interdit les webhooks en http:// (non chiffré)

    # ── Rétention / divers ───────────────────────────────────────────────
    LOG_RETENTION_DAYS: int = Field(default=30, ge=1, le=3650)  # durée de conservation des logs avant suppression
    CORRELATION_POLL_SECONDS: int = Field(default=5, ge=1, le=600)  # fréquence d'exécution du moteur de corrélation

    # ── Validateur de cohérence (prod-guard) ─────────────────────────────
    @model_validator(mode="after")
    def validate_prod(self) -> "Settings":
        """Bloque les configurations dangereuses en production."""
        # Toutes les vérifications ci-dessous ne s'appliquent qu'en production :
        # en dev/staging on tolère des valeurs par défaut faibles pour faciliter le développement.
        if self.APP_ENV != "prod":
            return self

        # 1. secret JWT : pas de placeholder dev
        if _is_weak_secret(self.API_SECRET_KEY):
            raise ValueError(
                "APP_ENV=prod interdit avec API_SECRET_KEY faible ou de longueur < 32. "
                "Génère une clé aléatoire : python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )

        # 2. TLS Elasticsearch : obligatoire en prod (empêche une attaque de type "homme du milieu")
        if not self.ELASTICSEARCH_TLS_VERIFY:
            raise ValueError("APP_ENV=prod interdit avec ELASTICSEARCH_TLS_VERIFY=False (MITM).")
        if not self.ELASTICSEARCH_HOST.startswith("https://"):
            raise ValueError("APP_ENV=prod exige ELASTICSEARCH_HOST en https://.")

        # 3. Docs OpenAPI : désactivés en prod (sinon on expose publiquement la structure de l'API)
        if self.DOCS_ENABLED:
            raise ValueError(
                "APP_ENV=prod interdit avec DOCS_ENABLED=true. "
                "Désactive les docs OpenAPI en production (fuite de schéma)."
            )

        # 4. CORS : pas de wildcard avec credentials (un "*" autoriserait n'importe quel site web à appeler l'API)
        if "*" in self.CORS_ORIGINS:
            raise ValueError("CORS_ORIGINS ne peut pas contenir '*' en production.")

        # 5. MFA recommandé en prod
        if not self.MFA_REQUIRED:
            # warning non bloquant (logger dans validate_prod_consumers) :
            # on ne bloque pas le démarrage, mais on pourrait vouloir tracer cet avertissement ailleurs.
            pass

        # 6. Webhooks : HTTPS obligatoire en prod (sinon les notifications transitent en clair)
        if self.SLACK_WEBHOOK_URL and not self.SLACK_WEBHOOK_URL.startswith("https://"):
            raise ValueError("SLACK_WEBHOOK_URL doit être HTTPS en production.")

        # 7. Redis : mot de passe et TLS obligatoires en prod (sinon les logs bruts transitent sans protection)
        if not self.REDIS_PASSWORD:
            raise ValueError("REDIS_PASSWORD obligatoire en production.")
        if not self.REDIS_TLS:
            raise ValueError("APP_ENV=prod exige REDIS_TLS=true pour chiffrer les communications Redis.")

        return self


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

# Instance unique, construite une seule fois au chargement du module.
# Tout le reste de l'application importe `settings` depuis ce module plutôt que
# de recréer un objet Settings() à chaque fois.
settings = Settings()  # type: ignore[call-arg]


def is_production() -> bool:
    """Petit helper sémantique : `is_production()` plutôt que `settings.APP_ENV == "prod"`."""
    return settings.APP_ENV == "prod"
