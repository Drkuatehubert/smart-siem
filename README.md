# Smart SIEM — UCAC-ICAM

> Projet intégrateur transversal 2026  
> Université Catholique d'Afrique Centrale — Institut Catholique de l'Afrique Centrale

Plateforme de cybersécurité full-stack couvrant la collecte de logs, la détection d'anomalies, la corrélation MITRE ATT&CK, la réponse automatisée (SOAR) et la supervision temps réel.

---

## Table des matières

- [Architecture](#architecture)
- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation rapide](#installation-rapide)
- [Variables d'environnement](#variables-denvironnement)
- [Structure du projet](#structure-du-projet)
- [Services Docker](#services-docker)
- [API Backend](#api-backend)
- [Authentification & RBAC](#authentification--rbac)
- [Moteur de corrélation](#moteur-de-corrélation)
- [Pipeline SOAR](#pipeline-soar)
- [Sécurité](#sécurité)
- [Équipe](#équipe)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet / LAN                        │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS :443
                    ┌──────▼──────┐
                    │    Nginx     │  Reverse proxy + TLS
                    └──┬───────┬──┘
               :3000   │       │  :8000
        ┌──────────────▼─┐  ┌──▼────────────────┐
        │  Frontend React │ │  Backend FastAPI  │
        │  (TypeScript)   │ │  (Python 3.12)    │
        └─────────────────┘ └───┬───────────┬───┘
                                │           │
              ┌─────────────────┤           ├────────────────┐
              │                 │           │                │
       ┌──────▼──────┐  ┌───────▼───┐  ┌───▼────────┐  ┌─────▼──────┐
       │Elasticsearch│  │PostgreSQL │  │   Redis    │  │ Normalizer │
       │ (via ngrok) │  │  :5432    │  │   :6379    │  │ API :8443  │
       └─────────────┘  └───────────┘  └─────┬──────┘  └────────────┘
                                             │
                              ┌──────────────┴───────────────┐
                              │                              │
                    ┌─────────▼────────┐           ┌─────────▼───────┐
                    │Moteur Corrélation│        v  │   SOAR Worker   │
                    │ (MITRE ATT&CK)   │──lpush───►│ pfSense / AD    │
                    └──────────────────┘           └─────────────────┘
```

---

## Fonctionnalités

### Collecte & Normalisation
- Réception de logs via **Syslog/TLS** (port 6514) et **HTTPS** (port 8443)
- Normalisation en format JSON structuré (CEF-like)
- Indexation dans Elasticsearch (`siem-logs-*`)

### Tableau de bord temps réel
- Volume de logs sur 24 h avec graphique horaire (Area chart)
- Compteurs d'alertes ouvertes / critiques (source PostgreSQL, fallback ES)
- Score de posture de sécurité calculé dynamiquement
- Répartition des alertes par niveau (Bar chart)
- Cache localStorage 30 s — pas de re-fetch à chaque navigation de page
- Bouton **Actualiser** pour forcer le rechargement depuis l'API

### Investigation des logs
- Filtres multi-critères : type, sévérité, plage horaire, IP source, utilisateur
- Limite 200 résultats par requête
- Export **CSV** (colonnes normalisées, UTF-8 BOM, nom horodaté)
- Export **PDF** via impression navigateur avec coloration par sévérité
- Bouton de réinitialisation des filtres + rechargement API

### Alertes & Incidents
- Cycle de vie complet : `open → investigating → closed`
- Niveaux : INFO / WARNING / HIGH / CRITICAL
- Liaison automatique alerte → incident via le moteur de corrélation

### Règles de corrélation (MITRE ATT&CK)
- Types supportés : `threshold`, `pattern`, `behavioral`, `composite`, `cross_source`
- Métadonnées : tactique MITRE, technique MITRE, score de confiance, fenêtre temporelle
- Activation/désactivation à la volée (`PATCH /rules/{id}/toggle`)

### UEBA — Analyse comportementale
- Profils de risque par utilisateur (`risk_score_current`)
- Détection d'anomalies comportementales (Isolation Forest, One-Class SVM via scikit-learn)
- Scores mis à jour périodiquement par un worker dédié (APScheduler)

### Threat Intelligence
- Enrichissement des alertes avec des indicateurs de compromission (IoC)

### Compliance
- Tableaux de conformité référentiels (NIS2, ISO 27001, PCI-DSS)

### SOAR — Réponse automatisée
- File Redis `soar_alerts` alimentée par le moteur de corrélation pour les niveaux HIGH/CRITICAL
- Playbooks configurables : **pfSense** (block IP via SSH), **Active Directory** (désactivation compte LDAP)
- Mode CONFIRM : délai de validation configurable (`CONFIRM_DELAY_SECONDS`) avant exécution
- Reconnexion automatique Redis avec backoff 5 s

### Reporting
- Génération de rapports PDF (ReportLab) et Excel (openpyxl)
- Exports d'audit horodatés

---

## Prérequis

| Outil | Version minimale |
|---|---|
| Docker Desktop | 4.x |
| Docker Compose | v2 (`docker compose`) |
| Git | 2.x |

Aucune installation Python ou Node.js locale requise — tout tourne en conteneur.

---

## Installation rapide

```bash
# 1. Cloner le dépôt
git clone <url-du-repo> smart-siem
cd smart-siem

# 2. Créer le fichier de configuration
cp .env.example .env
# → éditer .env avec vos valeurs (voir section ci-dessous)

# 3. Démarrer tous les services
docker compose up -d

# 4. Vérifier que tout est sain
docker compose ps
```

L'interface est disponible sur **https://localhost** (via Nginx) ou **http://localhost:3000** (frontend direct).  
L'API est disponible sur **http://localhost:8000** — documentation Swagger : `http://localhost:8000/docs`.

### Rebuild d'un service spécifique

```bash
docker compose up -d --build backend
docker compose up -d --build soar-worker
docker compose up -d --build correlation
```

### Logs en temps réel

```bash
docker compose logs -f backend
docker compose logs -f soar-worker
docker compose logs -f correlation
```

---

## Variables d'environnement

Créer un fichier `.env` à la racine :

```env
# Elasticsearch (instance partagée via ngrok ou locale)
ELASTICSEARCH_HOST=https://votre-instance.ngrok-free.dev
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=votre-mot-de-passe

# JWT
JWT_SECRET=une-chaine-aleatoire-longue-et-secrete
JWT_EXPIRY_MINUTES=480
JWT_REFRESH_EXPIRY_MINUTES=10080

# SOAR — pfSense
PFSENSE_HOST=192.168.1.1
PFSENSE_USER=admin
PFSENSE_PASSWORD=votre-mot-de-passe
PFSENSE_PORT=22

# SOAR — Active Directory
AD_HOST=192.168.1.10
AD_PORT=389
AD_USER=CN=admin,DC=domain,DC=local
AD_PASSWORD=votre-mot-de-passe
AD_BASE_DN=DC=domain,DC=local
AD_TARGET_OU=OU=Utilisateurs,DC=domain,DC=local

# SOAR — Comportement
CONFIRM_DELAY_SECONDS=60
CELERY_BROKER=redis://redis:6379/0
```

> PostgreSQL et Redis n'ont pas besoin d'être configurés dans `.env` : leurs credentials sont définis directement dans `docker-compose.yml`.

---

## Structure du projet

```
smart-siem/
├── backend/                      # API FastAPI (Python 3.12)
│   ├── app/
│   │   ├── api/v1/               # Endpoints REST par domaine
│   │   │   ├── auth/             #  Login, refresh token, MFA TOTP
│   │   │   ├── dashboard/        #  Résumé temps réel
│   │   │   ├── logs/             #  Investigation logs Elasticsearch
│   │   │   ├── alerts/           #  Alertes + déclenchement SOAR
│   │   │   ├── incidents/        #  Gestion des incidents
│   │   │   ├── rules/            #  Règles de corrélation MITRE
│   │   │   ├── ueba/             #  Profils comportementaux
│   │   │   ├── agents/           #  Agents EDR
│   │   │   ├── playbooks/        #  Playbooks SOAR
│   │   │   ├── reports/          #  Génération de rapports
│   │   │   ├── compliance/       #  Tableaux de conformité
│   │   │   ├── users/            #  Gestion des utilisateurs
│   │   │   └── audit/            #  Journaux d'audit
│   │   └── core/                 #  ES client, PG pool, Redis, RBAC, JWT
│   └── Dockerfile
│
├── frontend/                     # React 18 + TypeScript + Tailwind CSS
│   └── src/
│       ├── components/pages/     # 13 vues (Dashboard, Logs, Alertes…)
│       ├── Services/             # Clients API (axios)
│       └── types.ts              # Types TypeScript partagés
│
├── soar/                         # Worker SOAR
│   ├── worker.py                 #  Boucle Redis BLPOP + reconnexion auto
│   ├── orchestrator.py           #  Dispatch vers les playbooks
│   ├── executor.py               #  Exécution pfSense SSH / AD LDAP
│   ├── policy.py                 #  Règles de décision (mode CONFIRM)
│   ├── alerting.py               #  Notifications
│   ├── config.py                 #  Chargement des variables d'env
│   └── Dockerfile
│
├── correlation/                  # Dockerfile du moteur de corrélation
│   └── Dockerfile
│
├── temp-data/                    # Sources du moteur de corrélation
│   ├── correlation_engine_2.py   #  Moteur MITRE ATT&CK (asyncio)
│   ├── requirements.txt
│   └── bd_schema/                #  Schéma SQL PostgreSQL (init.sql)
│
├── COLLECTE & NORMALISATION/     # Normalizer API (Syslog/HTTPS → ES)
│   └── normalizer-api/
│
├── reporting/                    # Service de génération de rapports PDF/Excel
├── docker/                       # Config Nginx, certs TLS, config ES
├── docs/                         # Rapport de sécurité
├── .github/workflows/ci.yml      # Pipeline CI GitHub Actions
└── docker-compose.yml
```

---

## Services Docker

| Conteneur | Image / Build | Port exposé | Rôle |
|---|---|---|---|
| `siem-nginx` | `nginx:alpine` | 80, 443 | Reverse proxy TLS |
| `siem-frontend` | `./frontend` | 3000 | Interface React |
| `siem-backend` | `./backend` | 8000 | API FastAPI |
| `siem-postgres` | `postgres:16-alpine` | 5432 | Base relationnelle (alertes, règles, incidents…) |
| `siem-redis` | `redis:7-alpine` | 6379 | Queue SOAR + rate limiting JWT |
| `siem-normalizer` | `./COLLECTE & NORMALISATION/normalizer-api` | 8443 | Collecte & normalisation des logs |
| `siem-correlation` | `./temp-data` + `./correlation/Dockerfile` | — | Moteur de corrélation MITRE ATT&CK |
| `siem-soar-worker` | `.` + `soar/Dockerfile` | — | Worker SOAR (pfSense / AD) |
| `siem-reporting` | `./reporting` | — | Génération de rapports PDF/Excel |

---

## API Backend

Base URL : `http://localhost:8000/api/v1`  
Documentation interactive : `http://localhost:8000/docs`

| Méthode | Endpoint | Description |
|---|---|---|
| `POST` | `/auth/login` | Authentification — retourne JWT + refresh token |
| `POST` | `/auth/refresh` | Renouvellement du token d'accès |
| `GET` | `/dashboard/summary` | Résumé temps réel (logs 24h, alertes, graphes) |
| `GET` | `/logs` | Liste des logs avec filtres (max 200) |
| `GET` | `/alerts` | Alertes actives |
| `GET` | `/alerts/{id}` | Détail d'une alerte |
| `GET` | `/incidents` | Incidents en cours |
| `GET/POST` | `/rules` | Règles de corrélation |
| `PATCH` | `/rules/{id}/toggle` | Activer / désactiver une règle |
| `GET` | `/agents` | Agents EDR enregistrés |
| `GET` | `/ueba/profiles` | Profils comportementaux UEBA |
| `GET` | `/playbooks` | Playbooks SOAR disponibles |
| `GET` | `/reports` | Rapports générés |
| `GET` | `/compliance` | Données de conformité |
| `GET` | `/users` | Gestion des utilisateurs (admin uniquement) |
| `GET` | `/audit/logs` | Journaux d'audit |

---

## Authentification & RBAC

Authentification par **JWT HS256** avec refresh token. MFA disponible via **TOTP RFC 6238** (compatible Google Authenticator, Authy, Microsoft Authenticator).

| Rôle | Accès |
|---|---|
| `analyste` | Lecture logs, alertes, incidents, règles ; écriture commentaires incidents |
| `administrateur` | Toutes permissions + gestion utilisateurs, règles, playbooks |
| `auditeur` | Lecture seule sur logs, alertes, rapports, journaux d'audit |

Les mots de passe sont hashés en **bcrypt (rounds=12)**. Le rate limiting s'appuie sur Redis (`redis://redis:6379/1`).

---

## Moteur de corrélation

Le moteur (`temp-data/correlation_engine_2.py`) tourne en boucle asyncio et évalue les logs entrants contre les règles stockées dans PostgreSQL.

**Types de règles supportés** :

| Type | Description |
|---|---|
| `threshold` | Seuil de count sur une fenêtre temporelle |
| `pattern` | Correspondance de motif dans les champs de log |
| `behavioral` | Déviation par rapport au profil UEBA |
| `composite` | Combinaison logique de plusieurs règles |
| `cross_source` | Corrélation multi-sources (ex. : firewall + AD simultanément) |

Quand une alerte de niveau **HIGH** ou **CRITICAL** est générée, le moteur publie dans la file Redis `soar_alerts` via `LPUSH` pour déclencher le worker SOAR.

---

## Pipeline SOAR

```
Moteur de corrélation
        │
        │  LPUSH "soar_alerts"  (payload JSON)
        ▼
    Redis :6379
        │
        │  BLPOP (timeout=5s, socket_timeout=None)
        ▼
   soar-worker
        │
        ├── pfSense SSH ──► Ajout règle firewall "block <IP>"
        └── Active Directory LDAP ──► Désactivation du compte utilisateur
```

Le worker se reconnecte automatiquement à Redis en cas de coupure (backoff 5 s). En mode CONFIRM, un délai configurable (`CONFIRM_DELAY_SECONDS`, défaut 60 s) permet d'annuler l'action avant qu'elle soit exécutée.

---

## Sécurité

| Mesure | Détail |
|---|---|
| Transport | TLS 1.2+ sur toutes les communications externes (Nginx) |
| Mots de passe | bcrypt rounds=12 — jamais stockés en clair |
| Sessions | JWT HS256 avec expiration configurable (défaut 8 h) |
| MFA | TOTP RFC 6238 (Google Authenticator compatible) |
| Rate limiting | Redis-backed, par endpoint et par IP |
| Réseau Docker | Bridge isolé `siem-network` — pas d'exposition directe des BDD |
| RBAC | 3 rôles avec permissions granulaires vérifiées côté backend |
| Audit | Journalisation de toutes les actions administratives avec horodatage |

---

## Équipe

Projet réalisé dans le cadre du **Projet Intégrateur X3** — UCAC-ICAM Douala, promotion 2026.

| Rôle | Responsabilité |
|---|---|
| Chef de projet & Sécurité | Architecture, JWT/RBAC, SOAR, moteur de corrélation, backend |
| Ingénieur Infrastructure | Docker, Nginx, agents EDR, Syslog |
| Ingénieur Data | Normalisation, Elasticsearch, UEBA (ML) |
| Développeur Backend | API logs, alertes, incidents, rapports |
| Développeur Frontend | Dashboard, interface React, exports CSV/PDF |

---

*Smart SIEM — UCAC-ICAM — Projet intégrateur 2026*
