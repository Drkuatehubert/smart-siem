# Structure Git Exacte et Complète — Smart SIEM

> Basée sur : **SIEM Intelligent V1.docx** + **SmartSIEM_Analyse_Technique.docx**  
> Équipe : 5 étudiants · Durée : 2 semaines · Stack : FastAPI · Elasticsearch · React · Docker

---

## 🗂️ Vue d'ensemble de la racine

```
smart-siem/
├── .github/
├── backend/
├── collectors/
├── correlation/
├── frontend/
├── soar/
├── reporting/
├── docker/
├── scripts/
├── tests/
├── docs/
├── .gitignore
├── .env.example
├── docker-compose.yml
├── docker-compose.dev.yml
└── README.md
```

---

## 📁 Structure Complète Fichier par Fichier

```
smart-siem/
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                        # Pipeline CI : lint + tests + build images
│   │   ├── cd.yml                        # Pipeline CD : push vers registry
│   │   └── security-scan.yml            # Scan Trivy / Bandit sur chaque PR
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── CODEOWNERS                        # Reviewers par module
│
├── backend/                              # ── COUCHE 7 : API REST FastAPI ──
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                       # Point d'entrée FastAPI + lifespan
│   │   ├── config.py                     # Settings (pydantic-settings, .env)
│   │   ├── dependencies.py               # Injection de dépendances (ES client, auth)
│   │   │
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   └── v1/
│   │   │       ├── __init__.py
│   │   │       ├── router.py             # Agrégation de tous les routers v1
│   │   │       │
│   │   │       ├── auth/
│   │   │       │   ├── __init__.py
│   │   │       │   ├── router.py         # POST /auth/login, GET /auth/me
│   │   │       │   ├── schemas.py        # LoginRequest, TokenResponse, UserProfile
│   │   │       │   └── service.py        # Logique JWT, bcrypt, RBAC
│   │   │       │
│   │   │       ├── users/
│   │   │       │   ├── __init__.py
│   │   │       │   ├── router.py         # CRUD /users, /users/{id}/role
│   │   │       │   ├── schemas.py        # UserCreate, UserUpdate, UserOut
│   │   │       │   └── service.py        # idx-users ES operations
│   │   │       │
│   │   │       ├── logs/
│   │   │       │   ├── __init__.py
│   │   │       │   ├── router.py         # POST /logs/ingest, GET /logs/search
│   │   │       │   ├── schemas.py        # LogIngest, LogDocument, SearchQuery
│   │   │       │   └── service.py        # Écriture idx-logs, recherche multi-critères
│   │   │       │
│   │   │       ├── alerts/
│   │   │       │   ├── __init__.py
│   │   │       │   ├── router.py         # GET /alerts, PATCH /alerts/{id}/status
│   │   │       │   ├── schemas.py        # AlertOut, AlertStatusUpdate
│   │   │       │   └── service.py        # idx-alerts CRUD + notification trigger
│   │   │       │
│   │   │       ├── incidents/
│   │   │       │   ├── __init__.py
│   │   │       │   ├── router.py         # GET/POST/PATCH /incidents
│   │   │       │   ├── schemas.py        # IncidentCreate, IncidentOut
│   │   │       │   └── service.py        # idx-incidents, statut P1-P4
│   │   │       │
│   │   │       ├── rules/
│   │   │       │   ├── __init__.py
│   │   │       │   ├── router.py         # CRUD /rules (admin only)
│   │   │       │   ├── schemas.py        # RuleCreate, RuleOut
│   │   │       │   └── service.py        # idx-correlation-rules, validation DSL
│   │   │       │
│   │   │       ├── sources/
│   │   │       │   ├── __init__.py
│   │   │       │   ├── router.py         # CRUD /sources
│   │   │       │   ├── schemas.py        # SourceCreate, SourceOut
│   │   │       │   └── service.py        # idx-sources, statut collecte
│   │   │       │
│   │   │       ├── dashboard/
│   │   │       │   ├── __init__.py
│   │   │       │   ├── router.py         # GET /dashboard/summary, /dashboard/timeline
│   │   │       │   ├── schemas.py        # DashboardSummary, TimelinePoint
│   │   │       │   └── service.py        # Agrégations ES (top alertes, volume/heure)
│   │   │       │
│   │   │       ├── reports/
│   │   │       │   ├── __init__.py
│   │   │       │   ├── router.py         # POST /reports/generate, GET /reports/{id}
│   │   │       │   ├── schemas.py        # ReportRequest, ReportOut
│   │   │       │   └── service.py        # WeasyPrint PDF, openpyxl CSV/Excel
│   │   │       │
│   │   │       └── audit/
│   │   │           ├── __init__.py
│   │   │           ├── router.py         # GET /audit/logs (admin/auditeur only)
│   │   │           ├── schemas.py        # AuditLogOut
│   │   │           └── service.py        # idx-audit-log, append-only
│   │   │
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── security.py               # JWT encode/decode, password hash (bcrypt)
│   │   │   ├── rbac.py                   # Décorateurs @require_role, permission matrix
│   │   │   ├── elasticsearch.py          # Client ES singleton, index templates
│   │   │   ├── redis_client.py           # Redis Streams producer/consumer helpers
│   │   │   └── exceptions.py            # HTTPException handlers personnalisés
│   │   │
│   │   └── models/
│   │       ├── __init__.py
│   │       ├── user.py                   # Pydantic model idx-users
│   │       ├── role.py                   # Pydantic model idx-roles
│   │       ├── log.py                    # Pydantic model idx-logs
│   │       ├── alert.py                  # Pydantic model idx-alerts
│   │       ├── incident.py               # Pydantic model idx-incidents
│   │       ├── rule.py                   # Pydantic model idx-correlation-rules
│   │       ├── source.py                 # Pydantic model idx-sources
│   │       ├── playbook.py               # Pydantic model idx-playbooks
│   │       ├── audit_log.py              # Pydantic model idx-audit-log
│   │       ├── ueba_profile.py           # Pydantic model idx-ueba-profiles
│   │       └── retention_policy.py      # Pydantic model idx-retention-policies
│   │
│   ├── pyproject.toml                    # Dépendances Python (uv / pip)
│   ├── requirements.txt                  # Pin des versions de production
│   ├── requirements-dev.txt             # pytest, httpx, ruff, mypy
│   ├── Dockerfile                        # Image Python 3.12-slim
│   └── .env.example                      # Variables d'environnement backend
│
│
├── collectors/                           # ── COUCHES 1 & 2 : Collecte & Broker ──
│   │
│   ├── syslog_receiver/                  # Récepteur Syslog UDP/TCP (port 514/6514)
│   │   ├── __init__.py
│   │   ├── main.py                       # Serveur asyncio UDP+TCP
│   │   ├── parser.py                     # Parsing RFC 3164 / RFC 5424
│   │   ├── tls_config.py                 # Certificats TLS port 6514
│   │   └── Dockerfile
│   │
│   ├── agent_linux/                      # Agent léger Linux (Filebeat custom)
│   │   ├── agent.py                      # Surveillance fichiers + envoi vers API
│   │   ├── config.yaml                   # Sources à surveiller, endpoint cible
│   │   ├── install.sh                    # Script d'installation systemd
│   │   └── README.md
│   │
│   ├── agent_windows/                    # Agent léger Windows (PowerShell + Python)
│   │   ├── agent.py                      # Lecture Event Log + envoi vers API
│   │   ├── config.yaml
│   │   ├── install.ps1                   # Script d'installation service Windows
│   │   └── README.md
│   │
│   └── normalizer/                       # ── COUCHE 3 : Normalisation & Enrichissement
│       ├── __init__.py
│       ├── main.py                       # Worker Redis Streams consumer
│       ├── parser_engine.py              # Dispatcher (Grok, Regex, JSON natif)
│       ├── grok_patterns/
│       │   ├── linux_syslog.grok
│       │   ├── windows_evtx.grok
│       │   ├── apache_access.grok
│       │   ├── cisco_firewall.grok
│       │   └── generic.grok
│       ├── tagger.py                     # Tagging criticité + catégorie fonctionnelle
│       ├── enricher.py                   # GeoIP, référentiels internes
│       ├── schema.py                     # Schéma JSON cible (6 champs obligatoires)
│       └── Dockerfile
│
│
├── correlation/                          # ── COUCHE 5 : Intelligence & Détection ──
│   ├── __init__.py
│   ├── engine.py                         # Worker principal : consomme idx-logs en continu
│   ├── rule_loader.py                    # Chargement des règles depuis idx-correlation-rules
│   ├── evaluators/
│   │   ├── __init__.py
│   │   ├── threshold.py                  # Règles à seuil (RF-COR-01)
│   │   └── sequential.py                # Règles séquentielles pattern-based (RF-COR-02)
│   │
│   ├── rules/                            # Règles YAML prédéfinies (versionables)
│   │   ├── brute_force_ssh.yaml          # RF-COR-01 : 5 échecs auth/30s → HIGH
│   │   ├── port_scan_detection.yaml      # MITRE T1046 : Reconnaissance
│   │   ├── lateral_movement.yaml         # MITRE T1021 : Mouvement latéral
│   │   ├── data_exfiltration.yaml        # MITRE T1041 : Exfiltration
│   │   ├── firewall_ad_correlation.yaml  # RF-COR-05 : Multi-sources
│   │   └── privilege_escalation.yaml     # MITRE T1068
│   │
│   ├── ueba/
│   │   ├── __init__.py
│   │   ├── profiler.py                   # Calcul profil comportemental (7j glissants)
│   │   ├── anomaly_detector.py           # Écart-type horaire + volumétrique
│   │   └── risk_scorer.py               # Score 0-100, seuil 80 → alerte UEBA
│   │
│   └── Dockerfile
│
│
├── soar/                                 # ── COUCHE 6 : Alertes & Réponse Automatisée ──
│   ├── __init__.py
│   ├── alerting.py                       # Création alerte + dispatch notifications
│   ├── notifiers/
│   │   ├── __init__.py
│   │   ├── email_notifier.py             # SMTP (RF-ALR-02)
│   │   ├── webhook_notifier.py           # Slack / Teams webhook
│   │   └── ticketing_notifier.py         # Optionnel : Jira/GLPI (RF-ALR-03)
│   │
│   ├── playbooks/                        # Playbooks SOAR (RF-ALR-04)
│   │   ├── __init__.py
│   │   ├── base_playbook.py              # Classe abstraite PlaybookExecutor
│   │   ├── block_ip.py                   # Blocage IP via API pare-feu / iptables
│   │   ├── disable_account.py            # Désactivation compte utilisateur
│   │   └── isolate_machine.py            # Isolation réseau machine compromise
│   │
│   └── Dockerfile
│
│
├── reporting/                            # ── Module Reporting PDF/CSV/Excel ──
│   ├── __init__.py
│   ├── generator.py                      # Orchestrateur de génération de rapports
│   ├── templates/
│   │   ├── report_daily.html             # Template Jinja2 rapport quotidien
│   │   ├── report_weekly.html            # Template Jinja2 rapport hebdomadaire
│   │   └── assets/
│   │       ├── logo.png
│   │       └── style.css
│   ├── pdf_renderer.py                   # WeasyPrint → PDF (RF-VIZ-03)
│   ├── excel_exporter.py                 # openpyxl → Excel / CSV (RF-VIZ-04)
│   ├── scheduler.py                      # APScheduler : génération automatique
│   └── Dockerfile
│
│
├── frontend/                             # ── COUCHE 7 : Interface React ──
│   ├── public/
│   │   ├── index.html
│   │   └── favicon.ico
│   │
│   ├── src/
│   │   ├── main.jsx                      # Point d'entrée React + Router
│   │   ├── App.jsx
│   │   ├── index.css                     # Variables CSS globales, reset
│   │   │
│   │   ├── api/
│   │   │   ├── axios.js                  # Instance axios + intercepteurs JWT
│   │   │   ├── auth.js                   # login(), logout(), me()
│   │   │   ├── logs.js                   # search(), ingest()
│   │   │   ├── alerts.js                 # list(), updateStatus()
│   │   │   ├── incidents.js              # CRUD incidents
│   │   │   ├── rules.js                  # CRUD règles de corrélation
│   │   │   ├── users.js                  # CRUD utilisateurs
│   │   │   ├── dashboard.js              # getSummary(), getTimeline()
│   │   │   └── reports.js                # generate(), download()
│   │   │
│   │   ├── store/
│   │   │   ├── index.js                  # Redux Toolkit store
│   │   │   ├── authSlice.js              # JWT, user, role
│   │   │   ├── alertsSlice.js
│   │   │   └── logsSlice.js
│   │   │
│   │   ├── components/
│   │   │   ├── common/
│   │   │   │   ├── Navbar.jsx
│   │   │   │   ├── Sidebar.jsx
│   │   │   │   ├── ProtectedRoute.jsx    # Guard RBAC côté frontend
│   │   │   │   ├── SeverityBadge.jsx     # INFO / WARNING / HIGH / CRITICAL
│   │   │   │   ├── StatusBadge.jsx       # ouvert / en_cours / résolu
│   │   │   │   ├── LoadingSpinner.jsx
│   │   │   │   └── ErrorBoundary.jsx
│   │   │   │
│   │   │   ├── charts/
│   │   │   │   ├── LogVolumeChart.jsx    # Chart.js : volume logs/heure
│   │   │   │   ├── AlertLevelDonut.jsx   # Répartition niveaux d'alerte
│   │   │   │   ├── SourceMap.jsx         # Carte des sources (Leaflet.js)
│   │   │   │   └── RiskTimeline.jsx      # Timeline interactive incidents
│   │   │   │
│   │   │   ├── alerts/
│   │   │   │   ├── AlertList.jsx         # Tableau triable + filtrable
│   │   │   │   ├── AlertCard.jsx         # Carte résumé alerte
│   │   │   │   └── AlertDetail.jsx       # Vue détail + actions analyste
│   │   │   │
│   │   │   ├── logs/
│   │   │   │   ├── LogSearch.jsx         # Formulaire recherche multi-critères
│   │   │   │   ├── LogTable.jsx          # Tableau de résultats horodatés
│   │   │   │   └── LogTimeline.jsx       # Timeline interactive (RF-REC-02)
│   │   │   │
│   │   │   ├── incidents/
│   │   │   │   ├── IncidentList.jsx
│   │   │   │   └── IncidentForm.jsx
│   │   │   │
│   │   │   └── admin/
│   │   │       ├── UserManager.jsx       # CRUD utilisateurs (admin)
│   │   │       ├── RuleManager.jsx       # CRUD règles corrélation (admin)
│   │   │       ├── SourceManager.jsx     # Gestion sources / agents
│   │   │       └── RetentionConfig.jsx   # Politique de rétention
│   │   │
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx             # Authentification locale
│   │   │   ├── DashboardAnalyst.jsx      # Vue Analyste SOC (RF-VIZ-02)
│   │   │   ├── DashboardRSSI.jsx         # Vue synthétique RSSI
│   │   │   ├── DashboardRealtime.jsx     # Flux temps réel (WebSocket)
│   │   │   ├── DashboardAudit.jsx        # Vue Auditeur conformité
│   │   │   ├── LogSearchPage.jsx         # Investigation logs
│   │   │   ├── AlertsPage.jsx            # Gestion alertes
│   │   │   ├── IncidentsPage.jsx         # Suivi incidents
│   │   │   ├── ReportsPage.jsx           # Génération rapports PDF/Excel
│   │   │   └── AdminPage.jsx             # Administration (admin only)
│   │   │
│   │   └── utils/
│   │       ├── dateUtils.js              # Formatage timestamps
│   │       ├── severityUtils.js          # Mapping couleurs criticités
│   │       └── rbacUtils.js              # Helpers permissions frontend
│   │
│   ├── package.json
│   ├── vite.config.js                    # Vite + proxy API dev
│   ├── .eslintrc.json
│   └── Dockerfile                        # Nginx multi-stage build
│
│
├── docker/                               # ── COUCHE 4 : Infrastructure Docker ──
│   │
│   ├── elasticsearch/
│   │   ├── elasticsearch.yml             # Config ES (cluster, TLS, mémoire)
│   │   ├── jvm.options                   # Heap size adapté à l'environnement
│   │   └── mappings/                     # Mappings ES des 13 index
│   │       ├── idx-users.json
│   │       ├── idx-roles.json
│   │       ├── idx-audit-log.json
│   │       ├── idx-sources.json
│   │       ├── idx-logs.json
│   │       ├── idx-correlation-rules.json
│   │       ├── idx-alerts.json
│   │       ├── idx-incidents.json
│   │       ├── idx-playbooks.json
│   │       ├── idx-soar-executions.json
│   │       ├── idx-ueba-profiles.json
│   │       ├── idx-ueba-events.json
│   │       └── idx-retention-policies.json
│   │
│   ├── nginx/
│   │   ├── nginx.conf                    # Reverse proxy HTTPS + terminaison TLS
│   │   ├── ssl/                          # ⚠️ Répertoire vide dans Git (.gitkeep)
│   │   │   └── .gitkeep                  # ← les certs sont générés localement, jamais commités
│   │   └── conf.d/
│   │       ├── api.conf                  # Proxy vers backend :8000
│   │       └── frontend.conf             # Proxy vers frontend :3000
│   │
│   ├── redis/
│   │   └── redis.conf                    # Redis Streams : persistance AOF
│   │
│   └── certs/
│       ├── generate-certs.sh             # ✅ Script génération (dans Git)
│       └── .gitkeep                      # ← ca.pem, *.crt, *.key générés localement, jamais commités
│
│
├── scripts/                              # ── Scripts utilitaires & données de test ──
│   ├── init_elasticsearch.py             # Création des 13 index + mappings au démarrage
│   ├── seed_data.py                      # Génération 1000+ logs simulés (Faker)
│   ├── seed_users.py                     # Création utilisateurs par défaut (admin/analyste/lecteur)
│   ├── seed_rules.py                     # Import des 6 règles YAML dans ES
│   ├── simulate_attack.py                # Simulation brute-force SSH → déclenche alerte
│   ├── simulate_lateral_movement.py      # Scénario MITRE T1021
│   ├── simulate_exfiltration.py          # Scénario MITRE T1041
│   ├── health_check.sh                   # Vérifie tous les endpoints /health
│   └── load_test.py                      # Test de charge : 50 000 events/heure (Locust)
│
│
├── tests/                                # ── Tests automatisés ──
│   ├── conftest.py                       # Fixtures pytest (client ES test, app FastAPI)
│   │
│   ├── unit/
│   │   ├── test_normalizer.py            # Parser Grok, tagger, enricher
│   │   ├── test_correlation_threshold.py # Règle seuil brute-force
│   │   ├── test_correlation_sequential.py
│   │   ├── test_security_jwt.py          # JWT encode/decode, expiration
│   │   ├── test_rbac.py                  # Permissions par rôle
│   │   └── test_ueba_scorer.py           # Score de risque dynamique
│   │
│   ├── integration/
│   │   ├── test_api_auth.py              # POST /auth/login, GET /auth/me
│   │   ├── test_api_logs.py              # POST /logs/ingest, GET /logs/search
│   │   ├── test_api_alerts.py            # GET /alerts, PATCH /alerts/{id}/status
│   │   ├── test_api_rules.py             # CRUD /rules (admin)
│   │   └── test_api_users.py             # CRUD /users (admin)
│   │
│   └── e2e/
│       ├── test_brute_force_scenario.py  # Scénario bout-en-bout : logs → alerte → notification
│       └── test_soar_playbook.py         # Alerte CRITICAL → playbook → vérification
│
│
├── docs/                                 # ── Documentation technique ──
│   ├── architecture.md                   # Schéma 8 couches + flux de données
│   ├── api_reference.md                  # Complément Swagger (exemples curl)
│   ├── database_schema.md                # 13 index ES + dictionnaire de données
│   ├── deployment_guide.md               # Guide déploiement Docker + variables
│   ├── security_report.md                # Rapport sécurité : TLS, RBAC, audit
│   ├── correlation_rules.md              # Documentation des 6 règles MITRE
│   ├── playbooks.md                      # Documentation des 3 playbooks SOAR
│   ├── maintenance.md                    # Politique de rétention, purge, archivage
│   └── adr/                              # Architecture Decision Records
│       ├── ADR-001-elasticsearch-only.md # Choix 100% Elasticsearch
│       ├── ADR-002-redis-streams.md      # Redis Streams vs Kafka
│       ├── ADR-003-fastapi.md            # FastAPI vs Flask vs Django
│       └── ADR-004-docker-compose.md    # Docker Compose vs Kubernetes
│
│
├── .gitignore
├── .env.example                          # Template variables d'environnement
├── docker-compose.yml                    # Stack complète production
├── docker-compose.dev.yml                # Override dev (hot-reload, ports exposés)
└── README.md                             # Guide d'installation complet
```

---

## 🚫 Fichiers EXCLUS de Git (générés à l'exécution)

```
# Secrets & credentials
.env                              ← contient mots de passe réels
docker/nginx/ssl/cert.pem
docker/nginx/ssl/key.pem
docker/certs/ca.pem
docker/certs/*.crt
docker/certs/*.key

# Volumes Docker (données runtime)
esdata/                           ← données Elasticsearch sur disque
redisdata/                        ← données Redis
reporting/generated_reports/      ← PDFs générés automatiquement

# Artefacts de build
backend/__pycache__/
backend/.venv/
frontend/node_modules/
frontend/dist/
*.pyc
*.log
```

---

## 📋 Fichiers clés détaillés

### `.gitignore`
```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
dist/
build/

# Node
node_modules/
frontend/dist/

# Environnement
.env
*.env.local
docker/certs/*.pem
docker/certs/*.crt
docker/certs/*.key
docker/nginx/ssl/

# Elasticsearch data (volumes locaux)
esdata/

# Logs
*.log
logs/

# IDE
.vscode/
.idea/
*.swp

# OS
.DS_Store
Thumbs.db

# Tests
.coverage
htmlcov/
.pytest_cache/
```

### `.env.example`
```env
# Elasticsearch
ELASTICSEARCH_HOST=http://elasticsearch:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=changeme
ELASTICSEARCH_TLS_VERIFY=false

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_STREAM_KEY=siem:logs:raw

# Backend API
API_SECRET_KEY=changeme-32-chars-minimum
JWT_ALGORITHM=HS256
JWT_EXPIRY_MINUTES=60
API_HOST=0.0.0.0
API_PORT=8000

# CORS
CORS_ORIGINS=http://localhost:3000,https://siem.local

# Notifications
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=siem@example.com
SMTP_PASSWORD=changeme
SMTP_FROM=siem@example.com

SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx

# Syslog TLS
SYSLOG_TLS_PORT=6514
SYSLOG_CERT_PATH=/certs/syslog-server.crt
SYSLOG_KEY_PATH=/certs/syslog-server.key

# Retention
LOG_RETENTION_DAYS=30
ARCHIVE_COLD_STORAGE_PATH=/archive
```

### `docker-compose.yml`
```yaml
version: "3.9"

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
      - ELASTIC_PASSWORD=${ELASTICSEARCH_PASSWORD}
      - xpack.security.enabled=true
    volumes:
      - esdata:/usr/share/elasticsearch/data
      - ./docker/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml
    ports:
      - "9200:9200"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9200/_cluster/health"]
      interval: 30s
      retries: 5

  redis:
    image: redis:7-alpine
    command: redis-server /usr/local/etc/redis/redis.conf
    volumes:
      - ./docker/redis/redis.conf:/usr/local/etc/redis/redis.conf
      - redisdata:/data
    ports:
      - "6379:6379"

  backend:
    build: ./backend
    env_file: .env
    depends_on:
      elasticsearch:
        condition: service_healthy
      redis:
        condition: service_started
    ports:
      - "8000:8000"
    volumes:
      - ./docker/certs:/certs:ro

  syslog-receiver:
    build: ./collectors/syslog_receiver
    env_file: .env
    ports:
      - "514:514/udp"
      - "514:514/tcp"
      - "6514:6514/tcp"
    volumes:
      - ./docker/certs:/certs:ro

  normalizer:
    build: ./collectors/normalizer
    env_file: .env
    depends_on:
      - redis
      - elasticsearch

  correlation:
    build: ./correlation
    env_file: .env
    depends_on:
      - elasticsearch
      - redis

  soar:
    build: ./soar
    env_file: .env
    depends_on:
      - elasticsearch
      - backend

  reporting:
    build: ./reporting
    env_file: .env
    depends_on:
      - elasticsearch
    volumes:
      - reports:/app/generated_reports

  frontend:
    build: ./frontend
    ports:
      - "3000:80"

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./docker/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./docker/nginx/conf.d:/etc/nginx/conf.d:ro
      - ./docker/nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - backend
      - frontend

volumes:
  esdata:
  redisdata:
  reports:
```

### `.github/workflows/ci.yml`
```yaml
name: CI Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    services:
      elasticsearch:
        image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
        env:
          discovery.type: single-node
          ES_JAVA_OPTS: -Xms256m -Xmx256m
        ports:
          - 9200:9200
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r backend/requirements-dev.txt
      - run: cd backend && pytest tests/ --cov=app --cov-report=xml -v
      - run: cd backend && ruff check app/

  frontend-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: cd frontend && npm ci && npm run lint

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Bandit (Python security)
        run: pip install bandit && bandit -r backend/app/ -ll
```

---

## 🌿 Stratégie de Branches Git

```
main                    ← Production stable (protégée, PR obligatoire)
  └── develop           ← Intégration continue (base de travail)
        ├── feature/col-01-syslog-receiver        # RF-COL-01
        ├── feature/col-03-normalizer-pipeline     # RF-COL-03/04
        ├── feature/sto-01-es-indexing             # RF-STO-01/02
        ├── feature/sec-01-auth-rbac               # RF-SEC-01/02
        ├── feature/cor-01-threshold-engine        # RF-COR-01/02
        ├── feature/cor-03-mitre-rules             # RF-COR-03/06
        ├── feature/alr-01-alert-system            # RF-ALR-01/02
        ├── feature/alr-04-soar-playbooks          # RF-ALR-04
        ├── feature/viz-01-dashboard               # RF-VIZ-01/02
        ├── feature/viz-03-pdf-reports             # RF-VIZ-03/04
        ├── feature/rec-01-log-search              # RF-REC-01/02
        ├── feature/ueba-profiler                  # RF-UEBA-01/02
        └── fix/                                   # Corrections de bugs
```

### Règles de gouvernance Git
- **Merge uniquement via Pull Request** avec relecture d'au moins 1 pair
- **Commits Conventionnels** : `feat:`, `fix:`, `docs:`, `test:`, `chore:`
- **Protection de `main`** : pas de push direct, CI obligatoire ✅
- **Standup quotidien** : mise à jour des branches + synchronisation

---

## 👥 Répartition des modules par rôle

| Module Git | Rôle responsable |
|---|---|
| `backend/api/v1/auth/`, `backend/core/security.py`, `backend/core/rbac.py` | Chef de Projet & Sécurité |
| `collectors/syslog_receiver/`, `collectors/agent_linux/`, `collectors/agent_windows/` | Ingénieur Infrastructure |
| `collectors/normalizer/`, `correlation/`, `correlation/ueba/` | Ingénieur Data |
| `backend/api/v1/` (logs, alerts, incidents, rules), `soar/` | Développeur Backend |
| `frontend/`, `reporting/` | Développeur Frontend |
| `docker/`, `.github/workflows/`, `scripts/` | DevOps (cumulé) |

---

## 📦 Total des fichiers

| Catégorie | Fichiers |
|---|---|
| Backend (FastAPI) | ~55 fichiers |
| Collectors + Normalizer | ~20 fichiers |
| Correlation + UEBA | ~15 fichiers |
| SOAR + Alerting | ~10 fichiers |
| Frontend (React) | ~40 fichiers |
| Docker + Config | ~25 fichiers |
| Tests | ~12 fichiers |
| Documentation | ~12 fichiers |
| CI/CD + Scripts | ~15 fichiers |
| **Total** | **~204 fichiers** |
