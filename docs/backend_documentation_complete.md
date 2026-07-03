# Documentation complète du backend Smart SIEM

## 1. Vue d’ensemble

Le backend Smart SIEM fournit la couche API, sécurité et orchestration du système. Il expose des endpoints pour l’authentification, la recherche de logs, la gestion des alertes, des incidents, des règles de corrélation, des sources, du dashboard et des rapports.

## 2. Architecture fonctionnelle

### Composants principaux
- Authentification et autorisation : JWT, RBAC, MFA TOTP, audit.
- Logs : recherche et consultation des données SIEM via Elasticsearch.
- Alertes et incidents : traitement des événements et suivi des réponses.
- Règles de corrélation : moteur de logique métier pour enrichir les alertes.
- Rapports : génération et export de rapports de sécurité.
- Workers : traitements asynchrones et planifiés.

### Modules backend
- backend/app/auth : authentification et tokens.
- backend/app/api/v1 : endpoints REST versionnés.
- backend/app/core : sécurité, RBAC, configuration, intégrations.
- backend/app/logs : recherche de logs.
- backend/app/alerts : gestion des alertes.
- backend/app/reports : génération de rapports.

## 3. API REST

### Base URL
- `/api/v1`

### Endpoints principaux
- Authentification : `/api/v1/auth/*`
- Logs : `/api/v1/logs/*`
- Alertes : `/api/v1/alerts`
- Incidents : `/api/v1/incidents`
- Règles : `/api/v1/rules`
- Sources : `/api/v1/sources`
- Dashboard : `/api/v1/dashboard/summary`
- Rapports : `/api/v1/reports`
- Audit : `/api/v1/audit/*`
- Utilisateurs : `/api/v1/users`

## 4. Sécurité

### Authentification
- JWT Bearer token.
- Tokens access/refresh.
- MFA TOTP optionnel.

### Autorisation
- RBAC basé sur des rôles : lecteur, analyste, administrateur, auditeur.
- Contrôle des permissions via dépendances FastAPI.

### Protection réseau
- CORS restreint.
- Security headers.
- Rate limiting.

## 5. Dépendances techniques

- FastAPI
- Pydantic
- Redis
- Elasticsearch
- JWT via python-jose
- BCrypt
- SlowAPI

## 6. Démarrage local

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## 7. Documentation interactive

L’API est exposée via Swagger UI à l’adresse :
- `/docs`
- `/redoc`

## 8. Points d’extension

- intégrer Elasticsearch en production
- brancher PostgreSQL pour les données métier
- connecter les modules playbooks et UEBA
- enrichir les schémas OpenAPI avec des exemples détaillés
