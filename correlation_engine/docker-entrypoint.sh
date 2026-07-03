#!/bin/sh
set -e

echo "[entrypoint] Seed des règles YAML -> PostgreSQL..."
python -m correlation_engine.seed_rules || echo "[entrypoint] Seed échoué (non bloquant, le moteur redémarrera le chargement) "

echo "[entrypoint] Démarrage du moteur de corrélation..."
exec python -m correlation_engine.engine
