# Architecture du Smart SIEM

## Vue d'ensemble

Smart SIEM (Système de Gestion et d'Analyse des Événements de Sécurité) est une plateforme complète de sécurité informatique construite en architecture microservices, orchestrée via Docker Compose.

```
Agents Linux/Windows ─┐
Syslog/UDP/TCP/TLS ───┤──> Redis Streams ──> Normalizer ──> Elasticsearch
API Ingest ────────────┘                          ▲              │
                                                  │       Correlation Engine
                                                  │              │
                                             ┌────┴─────┐  SOAR (Playbooks)
                                             │ Backend  │       │
                                             │ API      │  Notifiers (Email/Slack)
                                             └────┬─────┘       │
                                                  │              │
                                             Frontend (React) ──┘
                                                  │
                                             Nginx (TLS proxy)
```

---

## Structure des dossiers

```
Smart siem/
├── backend/               # API REST (FastAPI)
├── frontend/              # Interface utilisateur (React)
├── collectors/            # Collecte des logs
│   ├── syslog_receiver/   # Récepteur syslog UDP/TCP/TLS
│   ├── normalizer/        # Normalisation des logs
│   ├── agent_linux/       # Agent Linux (tail de fichiers)
│   └── agent_windows/     # Agent Windows (placeholder)
├── correlation/           # Moteur de corrélation MITRE ATT&CK + UEBA
├── soar/                  # SOAR (playbooks + notifications)
├── reporting/             # Génération de rapports
├── docker/                # Configuration infrastructure
│   ├── nginx/             # Reverse proxy TLS
│   ├── elasticsearch/     # Configuration ES
│   └── redis/             # Configuration Redis
├── scripts/               # Scripts d'initialisation et seed
├── tests/                 # Tests unitaires, intégration, e2e
└── docs/                  # Documentation
```

---

## Flux de données détaillé

### 1. Collecte (collectors/)

**syslog_receiver/** — Serveur asyncio qui écoute sur les ports UDP (514), TCP (601) et TLS (6514). Il parse les messages au format RFC 3164 et les publie dans le stream Redis `siem:logs:raw`.

**agent_linux/** — Script Python qui suit les fichiers (`tail -f`) comme `/var/log/auth.log`, `/var/log/syslog`, `/var/log/nginx/access.log` et les envoie via l'API REST (`POST /api/v1/logs/ingest`).

**Fichiers clés :**
- `collectors/syslog_receiver/main.py` — Boucle asyncio, écoute UDP, publie dans Redis
- `collectors/syslog_receiver/parser.py` — Expression régulière RFC 3164
- `collectors/agent_linux/agent.py` — File watcher, envoi HTTP vers l'API
- `collectors/agent_linux/config.yaml` — Configuration : cibles API, fichiers à surveiller

### 2. Normalisation (collectors/normalizer/)

Consommateur Redis (groupe de consommateurs) qui lit le stream `siem:logs:raw`, parse le message brut, lui attribue un type et une sévérité, l'enrichit (GeoIP), puis l'indexe dans Elasticsearch (`idx-logs`).

**Pipeline :** Parse → Tag → Enrich → Index

**Fichiers clés :**
- `collectors/normalizer/main.py` — Worker Redis consumer group, pipeline principal
- `collectors/normalizer/schema.py` — Schéma du document normalisé (6 champs obligatoires)
- `collectors/normalizer/parser_engine.py` — Dispatch selon le format (JSON natif ou Syslog RFC 3164)
- `collectors/normalizer/tagger.py` — Auto-tagging : sévérité (critical/warning/info) et type (auth/reseau/application/systeme)
- `collectors/normalizer/enricher.py` — Enrichissement GeoIP (placeholder)

### 3. Moteur de corrélation (correlation/)

Interroge Elasticsearch (`idx-logs`) à intervalle régulier, évalue les règles de corrélation et génère des alertes dans `idx-alerts`.

**Règles incluses (MITRE ATT&CK) :**

| Fichier | Tactique MITRE | Condition | Seuil | Sévérité |
|---|---|---|---|---|
| `brute_force_ssh.yaml` | T1110 (Brute Force) | 5 échecs SSH en 30s | HIGH |
| `port_scan_detection.yaml` | T1046 (Network Scanning) | 20 événements réseau en 60s | WARNING |
| `lateral_movement.yaml` | T1021 (Remote Services) | Connexion réseau + auth en 120s | HIGH |
| `data_exfiltration.yaml` | T1041 (Exfiltration) | 50 événements réseau en 300s | CRITICAL |
| `firewall_ad_correlation.yaml` | T1078 (Valid Accounts) | Blocage firewall + auth AD en 60s | HIGH |
| `privilege_escalation.yaml` | T1068 (Privilege Escalation) | 3 sudo en 60s | CRITICAL |

**Fichiers clés :**
- `correlation/engine.py` — Boucle principale : charge les règles → évalue → crée les alertes
- `correlation/rule_loader.py` — Charge les règles depuis `idx-correlation-rules`
- `correlation/rules/*.yaml` — 6 règles YAML avec mapping MITRE ATT&CK
- `correlation/evaluators/threshold.py` — Évaluateur par seuil (count dans une fenêtre)
- `correlation/evaluators/sequential.py` — Évaluateur séquentiel (conditions ordonnées)

### 3b. UEBA (correlation/ueba/)

Analyse comportementale des utilisateurs et entités :

- **profiler.py** — Calcule les profils comportementaux (heures typiques, volume moyen) sur 7 jours
- **anomaly_detector.py** — Détecte les anomalies : accès hors horaires, pics de volume (>3x moyenne)
- **risk_scorer.py** — Score de risque dynamique (80+ → alerte HIGH)

### 4. API REST (backend/)

FastAPI servant les endpoints REST pour le frontend et les outils externes.

**Couches :**
- `app/core/security.py` — JWT (création/décodage), bcrypt (hash/verify), dépendance `get_current_user`
- `app/core/rbac.py` — Matrice de permissions 3 rôles (Lecteur/Analyste/Admin), décorateurs `require_roles` / `require_permission`
- `app/core/elasticsearch.py` — Client AsyncElasticsearch Singleton
- `app/api/v1/*/` — Routeurs par domaine (auth, users, logs, alerts, incidents, rules, sources, dashboard, reports, audit)

**Fichiers clés :**
- `backend/app/main.py` — Point d'entrée FastAPI, CORS, handlers d'erreur, inclusion des routeurs
- `backend/app/config.py` — Configuration Pydantic Settings (lecture des variables d'environnement)

### 5. Frontend (frontend/)

React 18 + Vite + Redux Toolkit. Authentification JWT, routage avec guard.

**Pages :**
- `LoginPage.jsx` — Formulaire de connexion, dispatch `setAuth`
- `DashboardAnalyst.jsx` — Tableau de bord analyste avec cartes de statistiques
- `DashboardRSSI.jsx` — Tableau de bord RSSI (placeholder)
- `AlertsPage.jsx` — Gestion des alertes (placeholder)
- `LogSearchPage.jsx` — Recherche de logs (placeholder)
- `AdminPage.jsx` — Panneau d'administration (placeholder)

**Fichiers clés :**
- `frontend/src/App.jsx` — Routes principales
- `frontend/src/api/axios.js` — Instance Axios avec intercepteur JWT + redirection 401
- `frontend/src/store/` — Store Redux (authSlice + alertsSlice)
- `frontend/src/components/common/ProtectedRoute.jsx` — Garde d'authentification

### 6. SOAR (soar/)

Surveille les alertes et exécute des playbooks automatisés.

**Playbooks :**
- `block_ip.py` — Ajoute une règle iptables DROP (RF-ALR-04)
- `disable_account.py` — Désactive un compte dans `idx-users` (`is_active=False`)
- `isolate_machine.py` — Isolation réseau simulée (action manuelle requise)

**Fichiers clés :**
- `soar/alerting.py` — Dispatch des notifications (email + Slack) et exécution des playbooks
- `soar/playbooks/base_playbook.py` — Classe abstraite pour tous les playbooks
- `soar/notifiers/email_notifier.py` — Notification SMTP
- `soar/notifiers/webhook_notifier.py` — Webhook Slack/Teams
- `soar/notifiers/ticketing_notifier.py` — Intégration Jira/GLPI (placeholder)

### 7. Reporting (reporting/)

Génération de rapports PDF/Excel à partir de templates HTML.

**Fichiers clés :**
- `reporting/pdf_renderer.py` — PDF via WeasyPrint (TODO)
- `reporting/excel_exporter.py` — Excel via openpyxl (TODO)
- `reporting/scheduler.py` — Planification APScheduler (TODO)
- `reporting/templates/report_daily.html` — Template rapport quotidien
- `reporting/templates/report_weekly.html` — Template rapport hebdomadaire

---

## Liaisons entre les services

| Source | Destination | Mécanisme | Détail |
|---|---|---|---|
| `syslog_receiver` | Redis | Redis Streams | Publie dans `siem:logs:raw` |
| `normalizer` | Redis | Redis Streams (consumer group) | Lit `siem:logs:raw` |
| `normalizer` | Elasticsearch | HTTP (port 9200) | Indexe dans `idx-logs` |
| `correlation` | Elasticsearch | HTTP | Lit `idx-logs`, écrit dans `idx-alerts` |
| `backend` | Elasticsearch | HTTP (client async) | Lit/écrit dans 13 indices |
| `soar` | Elasticsearch | HTTP | Lit `idx-alerts`, écrit dans `idx-users` |
| `reporting` | Elasticsearch | HTTP | Lit tous les indices |
| `frontend` | `backend` | HTTP (REST) | Via Nginx ou proxy Vite (dev) |
| `agent_linux` | `backend` | HTTP (REST) | POST /api/v1/logs/ingest |
| `nginx` | `frontend` | Proxy HTTP | Sert les fichiers statiques |
| `nginx` | `backend` | Proxy HTTP | `/api/*` → `backend:8000` |

---

## Base de données partagée : Elasticsearch

Tous les services lisent et écrivent dans Elasticsearch. C'est le point central de la persistence.

**Indices :**

| Index | Créé par | Écrit par | Lu par |
|---|---|---|---|
| `idx-users` | `init_elasticsearch.py` | `backend`, `soar` | `backend` |
| `idx-roles` | `init_elasticsearch.py` | `seed_users.py` | `backend` |
| `idx-audit-log` | `init_elasticsearch.py` | `backend` | `backend` |
| `idx-sources` | `init_elasticsearch.py` | `backend` | `backend` |
| `idx-logs` | `init_elasticsearch.py` | `normalizer` | `backend`, `correlation`, `reporting` |
| `idx-correlation-rules` | `init_elasticsearch.py` | `seed_rules.py` | `correlation` |
| `idx-alerts` | `init_elasticsearch.py` | `correlation` | `backend`, `soar`, `reporting` |
| `idx-incidents` | `init_elasticsearch.py` | `backend` | `backend` |
| `idx-playbooks` | `init_elasticsearch.py` | - | `soar` |
| `idx-soar-executions` | `init_elasticsearch.py` | `soar` | `soar` |
| `idx-ueba-profiles` | `init_elasticsearch.py` | `correlation/ueba` | `correlation/ueba` |
| `idx-ueba-events` | `init_elasticsearch.py` | `correlation/ueba` | `correlation/ueba` |
| `idx-retention-policies` | `init_elasticsearch.py` | - | `reporting` |

---

## RBAC (Contrôle d'accès)

Matrice définie dans `backend/app/core/rbac.py` :

| Permission | Lecteur | Analyste | Admin |
|---|---|---|---|
| Logs : read/search | ✓ | ✓ | ✓ |
| Logs : ingest/flag | | ✓ | ✓ |
| Alerts : read | ✓ | ✓ | ✓ |
| Alerts : update | | ✓ | ✓ |
| Incidents : all | | ✓ | ✓ |
| Dashboard : read | ✓ | ✓ | ✓ |
| Rapports : read | ✓ | ✓ | ✓ |
| Rapports : generate | | ✓ | ✓ |
| Audit : read | | | ✓ |
| Users : CRUD | | | ✓ |
| Rules : CRUD | | lecture seul | ✓ |
| Sources : manage | | | ✓ |

Les admins voient toutes les organisations ; les autres utilisateurs sont filtrés par `org_scope`.

---

## Scripts d'initialisation (`scripts/`)

| Script | Action |
|---|---|
| `init_elasticsearch.py` | Crée les 13 indices Elasticsearch avec leurs mappings |
| `seed_users.py` | Crée 3 utilisateurs (admin/analyste/lecteur) + rôles |
| `seed_data.py` | Génère 1000+ logs simulés avec Faker |
| `seed_rules.py` | Importe les 6 règles YAML de corrélation dans ES |
| `simulate_attack.py` | Insère 10 logs SSH brute-force pour déclencher une alerte |
| `health_check.sh` | Vérifie l'état de l'API, ES, Redis |

**Ordre d'exécution recommandé :**
1. `init_elasticsearch.py`
2. `seed_users.py`
3. `seed_rules.py`
4. `seed_data.py` (optionnel)
5. `simulate_attack.py` (pour tester)

---

## Configuration et déploiement

**Fichiers Docker Compose :**
- `docker-compose.yml` — Production : 9 services + Nginx, healthchecks, dépendances
- `docker-compose.dev.yml` — Développement : hot-reload, ports exposés, pas de Nginx

**Variables d'environnement (`.env`) :**
- `ES_USER` / `ES_PASSWORD` — Authentification Elasticsearch
- `JWT_SECRET` / `JWT_EXPIRATION` — Clé et durée des tokens JWT
- `REDIS_HOST` / `REDIS_PORT` — Connexion Redis
- `SMTP_*` — Configuration email pour les notifications
- `SYSLOS_TLS_CERT` / `SYSLOS_TLS_KEY` — Certificats TLS syslog
- `LOGS_RETENTION_DAYS` — Durée de rétention des logs

**Infrastructure (`docker/`) :**
- `nginx/nginx.conf` — Terminaison TLS, HSTS, en-têtes de sécurité
- `elasticsearch/elasticsearch.yml` — Nœud unique, xpack.security activé
- `redis/redis.conf` — Persistance AOF, éviction LRU

---

## Tests (`tests/`)

| Dossier | Contenu |
|---|---|
| `tests/unit/test_security_jwt.py` | Tests bcrypt + JWT |
| `tests/unit/test_rbac.py` | 8 cas de test sur la matrice 3 rôles |
| `tests/unit/test_normalizer.py` | Tests du tagger + schéma |
| `tests/integration/test_api_auth.py` | Tests health, login, guard |
| `tests/e2e/` | Tests end-to-end (vides) |

Exécution : `pytest` (configuré dans `pyproject.toml`)

CI GitHub Actions (`.github/workflows/ci.yml`) : tests unitaires RBAC+JWT → Bandit → Ruff lint.

---

## Résumé des dépendances entre fichiers

```
.env ────────────────────────────> backend/app/config.py
                                        
docker-compose.yml ──────────────> Tous les Dockerfile
                                        
backend/app/core/security.py ────> backend/app/api/v1/auth/*.py
   │                                 backend/app/api/v1/*/ (via get_current_user)
   └──> JWT token ───────────────> frontend/src/api/axios.js (intercepteur)
                                        
backend/app/core/rbac.py ────────> backend/app/api/v1/*/ (décorateurs require_roles)
                                        
backend/app/core/elasticsearch.py ──> Tous les routeurs API v1
                                        
collectors/normalizer/main.py ───> parser_engine.py ──> tagger.py ──> enricher.py
   │                                  │
   └──> Elasticsearch idx-logs ────> correlation/engine.py
                                       │
                                       └──> Elasticsearch idx-alerts ────> soar/alerting.py
                                                                             │
                                                                       playbooks/*.py
                                                                       notifiers/*.py
                                        
scripts/init_elasticsearch.py ───> Crée les 13 indices
scripts/seed_users.py ───────────> backend/app/models/user.py (schéma)
scripts/seed_rules.py ───────────> correlation/rules/*.yaml (format)
```
