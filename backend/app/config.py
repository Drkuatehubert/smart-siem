"""
config.py — Configuration centralisée via variables d'environnement
Responsable : Chef de Projet & Sécurité
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # JWT
    API_SECRET_KEY: str = "changeme-minimum-32-chars-secret-key"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 60

    # Elasticsearch
    ELASTICSEARCH_HOST: str = "http://elasticsearch:9200"
    ELASTICSEARCH_USERNAME: str = "elastic"
    ELASTICSEARCH_PASSWORD: str = "changeme"
    ELASTICSEARCH_TLS_VERIFY: bool = False

    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_STREAM_KEY: str = "siem:logs:raw"

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # Notifications
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "siem@example.com"
    SLACK_WEBHOOK_URL: str = ""

    # Rétention
    LOG_RETENTION_DAYS: int = 30

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
