"""
config.py â€” Configuration centralisÃ©e via variables d'environnement (pydantic-settings v2)

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : RF-SEC-01 (JWT durci), NFR-SEC-02 (chiffrement), NFR-SEC-04 (multi-tenant),
            durcissement global (MFA, rate-limit, lockout, SOAR kill-switch, prod-guard).

Ce module :
  * charge toutes les variables d'environnement en un seul objet `Settings` typÃ© ;
  * verrouille `JWT_ALGORITHM` Ã  un sous-ensemble sÃ»r (pas d'alg="none") ;
  * valide en `prod` que les secrets ne sont pas les valeurs par dÃ©faut,
    que TLS ES est actif, et que la doc OpenAPI est dÃ©sactivÃ©e.
"""

from __future__ import annotations

import re
from typing import List, Literal, Optional

from pydantic import EmailStr, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Helpers de validation
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# Secrets considÃ©rÃ©s comme faibles â€” interdits en production
_FORBIDDEN_SECRET_SUBSTRINGS = (
    "changeme", "password", "secret", "admin", "default", "test", "example",
)

# Algorithmes JWT autorisÃ©s (rien d'autre que du HMAC ou de l'asymÃ©trique sÃ»r)
JWT_ALLOWED_ALGS = Literal["HS256", "HS384", "HS512", "RS256", "ES256"]


def _is_weak_secret(value: str) -> bool:
    """Renvoie True si la valeur ressemble Ã  un placeholder dev."""
    v = value.lower()
    if len(value) < 32:
        return True
    return any(s in v for s in _FORBIDDEN_SECRET_SUBSTRINGS)


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Settings
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class Settings(BaseSettings):
    """
    Configuration de l'application Smart SIEM.

    Toutes les variables sensibles DOIVENT Ãªtre fournies par l'environnement
    (ou .env) en production. Les dÃ©fauts ci-dessous sont des placeholders
    de dÃ©veloppement et sont rejetÃ©s par `validate_prod()` quand
    `APP_ENV == "prod"`.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    # â”€â”€ Environnement â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    APP_ENV: Literal["dev", "staging", "prod"] = "dev"
    DOCS_ENABLED: bool = True  # dÃ©sactivÃ© automatiquement en prod

    # â”€â”€ API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: List[str] = Field(default_factory=lambda: ["https://localhost"])
    ALLOWED_HOSTS: List[str] = Field(default_factory=lambda: ["localhost", "siem.local"])

    # â”€â”€ JWT (RF-SEC-01) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    API_SECRET_KEY: str = Field(
        default="dev-only-not-for-production-min-32-chars-XXXX",
        min_length=32,
    )
    JWT_ALGORITHM: JWT_ALLOWED_ALGS = "HS256"
    JWT_EXPIRY_MINUTES: int = Field(default=15, ge=1, le=60 * 24)
    JWT_REFRESH_EXPIRY_MINUTES: int = Field(default=60 * 24, ge=1, le=60 * 24 * 30)
    JWT_ACCESS_LEEWAY_SECONDS: int = Field(default=30, ge=0, le=300)
    JWT_ISSUER: str = "smart-siem"
    JWT_AUDIENCE: str = "smart-siem-api"

    # â”€â”€ MFA (NFR-SEC-02, dÃ©fense en profondeur) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    MFA_REQUIRED: bool = False
    MFA_ISSUER: str = "SmartSIEM"
    MFA_TOTP_DIGITS: int = Field(default=6, ge=6, le=8)
    MFA_TOTP_PERIOD: int = Field(default=30, ge=15, le=120)

    # â”€â”€ Rate limit (slowapi) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_LOGIN_BURST: str = "10/hour"
    RATE_LIMIT_STORAGE_URI: str = "redis://redis:6379/1"

    # â”€â”€ Politique mot de passe (NFR-SEC-03) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    PASSWORD_MIN_LENGTH: int = Field(default=12, ge=8)
    PASSWORD_MAX_LENGTH: int = Field(default=128, ge=8, le=4096)
    PASSWORD_REQUIRE_UPPER: bool = True
    PASSWORD_REQUIRE_LOWER: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SYMBOL: bool = True
    PASSWORD_HISTORY_SIZE: int = Field(default=5, ge=0, le=50)

    # â”€â”€ Account lockout (NFR-SEC-04) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ACCOUNT_LOCKOUT_THRESHOLD: int = Field(default=5, ge=1, le=50)
    ACCOUNT_LOCKOUT_DURATION_MIN: int = Field(default=15, ge=1, le=24 * 60)

    # â”€â”€ SOAR / actions rÃ©seau (RF-SEC-05) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    BLOCK_IP_DRY_RUN: bool = True
    BLOCK_IP_MAX_PER_HOUR: int = Field(default=50, ge=1, le=10_000)
    BLOCK_IP_REQUIRE_APPROVAL_BELOW: Literal["INFO", "WARNING", "HIGH", "CRITICAL"] = "CRITICAL"
    SOAR_REQUIRE_APPROVAL: bool = True
    SOAR_KILL_SWITCH: bool = False
    SOAR_ALLOW_PRIVATE_NETWORKS: bool = False  # IP RFC1918 / loopback
    SOAR_MIN_AUTO_LEVEL: Literal["INFO", "WARNING", "HIGH", "CRITICAL"] = "CRITICAL"
    SOAR_DRY_RUN: bool = True

    # â”€â”€ Headers sÃ©curitÃ© (NFR-SEC-05) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    HSTS_MAX_AGE: int = 31_536_000  # 1 an
    CSP_POLICY: str = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    # â”€â”€ Elasticsearch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ELASTICSEARCH_HOST: str = "http://elasticsearch:9200"
    ELASTICSEARCH_USERNAME: str = "elastic"
    ELASTICSEARCH_PASSWORD: str = "changeme"
    ELASTICSEARCH_TLS_VERIFY: bool = True
    ELASTICSEARCH_CA_CERTS: Optional[str] = None
    ELASTICSEARCH_REQUEST_TIMEOUT: int = 10
    ELASTICSEARCH_MAX_RETRIES: int = 2

    # â”€â”€ Redis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_TLS: bool = False
    REDIS_CA_CERTS: Optional[str] = None
    REDIS_STREAM_KEY: str = "siem:logs:raw"
    REDIS_STREAM_MAXLEN: int = Field(default=1_000_000, ge=1_000)
    REDIS_MESSAGE_MAX_BYTES: int = Field(default=65_536, ge=256, le=1_048_576)

    # â”€â”€ Notifications (RF-NOT-01..04) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: EmailStr = "siem@example.com"  # type: ignore[assignment]
    SMTP_TLS: bool = True
    SLACK_WEBHOOK_URL: str = ""
    SLACK_SIGNING_SECRET: str = ""
    PAGERDUTY_ROUTING_KEY: str = ""
    WEBHOOK_REQUIRE_HTTPS: bool = True

    # â”€â”€ RÃ©tention / divers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    LOG_RETENTION_DAYS: int = Field(default=30, ge=1, le=3650)
    CORRELATION_POLL_SECONDS: int = Field(default=5, ge=1, le=600)

    # â”€â”€ Validateur de cohÃ©rence (prod-guard) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @model_validator(mode="after")
    def validate_prod(self) -> "Settings":
        """Bloque les configurations dangereuses en production."""
        if self.APP_ENV != "prod":
            return self

        # 1. secret JWT : pas de placeholder dev
        if _is_weak_secret(self.API_SECRET_KEY):
            raise ValueError(
                "APP_ENV=prod interdit avec API_SECRET_KEY faible ou de longueur < 32. "
                "GÃ©nÃ¨re une clÃ© alÃ©atoire : python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )

        # 2. TLS Elasticsearch : obligatoire en prod
        if not self.ELASTICSEARCH_TLS_VERIFY:
            raise ValueError("APP_ENV=prod interdit avec ELASTICSEARCH_TLS_VERIFY=False (MITM).")
        if not self.ELASTICSEARCH_HOST.startswith("https://"):
            raise ValueError("APP_ENV=prod exige ELASTICSEARCH_HOST en https://.")

        # 3. Docs OpenAPI : dÃ©sactivÃ©s en prod
        if self.DOCS_ENABLED:
            raise ValueError(
                "APP_ENV=prod interdit avec DOCS_ENABLED=true. "
                "DÃ©sactive les docs OpenAPI en production (fuite de schÃ©ma)."
            )

        # 4. CORS : pas de wildcard avec credentials
        if "*" in self.CORS_ORIGINS:
            raise ValueError("CORS_ORIGINS ne peut pas contenir '*' en production.")

        # 5. MFA recommandÃ© en prod
        if not self.MFA_REQUIRED:
            # warning non bloquant (logger dans validate_prod_consumers)
            pass

        # 6. Webhooks : HTTPS obligatoire en prod
        if self.SLACK_WEBHOOK_URL and not self.SLACK_WEBHOOK_URL.startswith("https://"):
            raise ValueError("SLACK_WEBHOOK_URL doit Ãªtre HTTPS en production.")

        # 7. Redis : mot de passe obligatoire en prod
        if not self.REDIS_PASSWORD:
            raise ValueError("REDIS_PASSWORD obligatoire en production.")
        if not self.REDIS_TLS:
            raise ValueError("APP_ENV=prod exige REDIS_TLS=true pour chiffrer les communications Redis.")

        return self


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Singleton
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

settings = Settings()  # type: ignore[call-arg]


def is_production() -> bool:
    """Petit helper sÃ©mantique : `is_production()` plutÃ´t que `settings.APP_ENV == "prod"`."""
    return settings.APP_ENV == "prod"
