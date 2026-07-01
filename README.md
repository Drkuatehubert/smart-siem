# Smart SIEM — Système de Gestion et d'Analyse des Événements de Sécurité

> Projet intégrateur | Équipe 5 étudiants | 2 semaines

## Stack technique
- **Backend** : FastAPI (Python 3.12) + Elasticsearch 8 + Redis Streams
- **Frontend** : React + Vite
- **Infrastructure** : Docker Compose + Nginx (TLS)
- **Détection** : Moteur de corrélation MITRE ATT&CK + UEBA

## Démarrage rapide

```bash
# 1. Cloner
git clone https://github.com/votre-org/smart-siem.git && cd smart-siem

# 2. Configuration
cp .env.example .env
# Éditer .env avec vos valeurs

# 3. Certificats TLS
bash docker/certs/generate-certs.sh

# 4. Démarrer la stack
docker compose up -d

# 5. Initialiser Elasticsearch (13 index)
docker compose exec backend python scripts/init_elasticsearch.py

# 6. Données de test
docker compose exec backend python scripts/seed_users.py
docker compose exec backend python scripts/seed_data.py
docker compose exec backend python scripts/seed_rules.py
```

## Accès
| Service | URL | Identifiant |
|---|---|---|
| API Swagger | https://localhost/api/docs | — |
| Frontend | https://localhost | admin / Admin@2024! |
| Elasticsearch | https://localhost:9200 | elastic / (voir .env) |

## Architecture
Voir [docs/architecture.md](docs/architecture.md)

## Documentation cybersecurite
Voir [docs/cybersecurity/00_resume_global.md](docs/cybersecurity/00_resume_global.md) pour le resume des renforcements SOAR, TLS, UEBA et correlation.

## Équipe
| Rôle | Responsabilité |
|---|---|
| Chef de Projet & Sécurité | JWT, RBAC, audit, conformité |
| Ingénieur Infrastructure | Docker, agents, Syslog |
| Ingénieur Data | Normalisation, corrélation, UEBA |
| Développeur Backend | API logs, alertes, incidents |
| Développeur Frontend | Dashboard, recherche, rapports |
