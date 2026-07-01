# Spécification technique backend Smart SIEM

## 1. Objectif général

Le backend doit fournir une couche d’orchestration, d’exposition API et de coordination entre :

- PostgreSQL : stockage métier des alertes, profils UEBA, règles de corrélation, exécutions de playbooks, rapports et métadonnées associées ;
- Elasticsearch : stockage et recherche des logs SIEM (indices de type `siems-logs-*`) ;
- modules métier internes : correlation engine, UEBA worker, playbooks et génération de rapports.

Le backend doit permettre :

1. l’exposition des données au frontend ;
2. l’automatisation des traitements périodiques ;
3. l’exécution manuelle des playbooks ;
4. la génération de rapports ;
5. le contrôle d’accès par RBAC.

---

## 2. Périmètre fonctionnel détaillé

### 2.1 Alertes

#### Besoin métier

Le système doit détecter, exposer et traiter les alertes issues de PostgreSQL, de façon automatique et transparente pour l’utilisateur final.

#### Règles métier

- Les alertes doivent être récupérées depuis la table `alerts`.
- Une alerte est considérée comme "active" si elle n’est pas résolue et qu’aucune procédure n’a encore été lancée.
- Le worker doit scruter régulièrement cette table et produire un flux de travail pour le frontend et le moteur de playbooks.
- Lorsqu’une alerte est identifiée, le système doit déterminer le playbook adapté et déclencher son exécution.

#### Exigences techniques

- Worker de fond périodique ou continu.
- Lecture périodique de la table `alerts`.
- Filtrage sur :
  - status != resolved ;
  - execution_status != started/completed/failed selon la logique métier retenue ;
  - priority/severity si disponible ;
  - created_at / updated_at.
- Appel au module playbook avec le playbook associé.

#### Routes backend attendues

- `GET /api/v1/alerts` : liste des alertes avec filtres modulables.
- `GET /api/v1/alerts/{id}` : détail d’une alerte.
- `POST /api/v1/alerts` : création manuelle d’une alerte.
- `PATCH /api/v1/alerts/{id}` : mise à jour d’une alerte.
- `DELETE /api/v1/alerts/{id}` : suppression d’une alerte.

#### Détail de l’alerte complète

Une route dédiée doit retourner :

- les données de l’alerte depuis PostgreSQL ;
- les logs Elasticsearch liés à cette alerte ;
- les métadonnées de correlation rules associées ;
- les playbook executions liées.

Cette route devra être construite à partir de :

- `alerts.id` ;
- `alerts.related_log_ids` ou champs équivalents ;
- `alerts.correlation_rule_id` ou champs associés ;
- l’index Elasticsearch `siems-logs-*` ;
- la table de suivi des exécutions de playbooks.

---

### 2.2 Logs Elasticsearch

#### Besoin métier

Le frontend doit pouvoir rechercher les logs SIEM de manière flexible et rapide, avec des filtres modulables sur les champs importants.

#### Exigences techniques

- Recherche dans les indices Elasticsearch de type `siems-logs-*`.
- Support de filtres optionnels sur :
  - `timestamp` ;
  - `event_action` ;
  - `source_ip` ;
  - `destination_ip` ;
  - `host` ;
  - `user` ;
  - `severity` ;
  - `mitre_technique_id` ;
  - `alert_id` ;
  - `correlation_rule_id`.
- Si un filtre est absent, il doit être ignoré sans casser la requête.
- La recherche doit permettre un mode simple et un mode avancé.

#### Routes backend attendues

- `GET /api/v1/logs/search` : recherche de logs via query params.
- `GET /api/v1/logs/{id}` : détail d’un log.
- `GET /api/v1/logs/mitre/aggregate` : agrégation par technique MITRE.

#### Logique de recherche

Le backend doit construire dynamiquement un bool query Elasticsearch à partir des paramètres présents.

Exemple de filtres supportés :

- `?source_ip=10.0.0.5`
- `?destination_ip=192.168.1.1`
- `?event_action=login`
- `?start_time=2026-06-01T00:00:00Z&end_time=2026-06-30T23:59:59Z`
- `?severity=high`

---

### 2.3 Règles de corrélation

#### Besoin métier

Le backend doit exposer les règles de corrélation utilisées pour générer ou enrichir les alertes.

#### Exigences techniques

- Stockage et lecture depuis PostgreSQL.
- Support du CRUD.
- Activation/désactivation d’une règle.
- Liaison possible avec les alertes et les logs.

#### Routes backend attendues

- `GET /api/v1/correlation-rules`
- `GET /api/v1/correlation-rules/{id}`
- `POST /api/v1/correlation-rules`
- `PATCH /api/v1/correlation-rules/{id}`
- `DELETE /api/v1/correlation-rules/{id}`
- `PATCH /api/v1/correlation-rules/{id}/toggle`

---

### 2.4 Playbooks et exécution semi-automatique

#### Besoin métier

Le système doit pouvoir exécuter des playbooks manuellement ou automatiquement à partir d’une alerte.

#### Règles métier

- Une exécution de playbook doit être liée à une alerte et à un playbook défini.
- Suivant le playbook exécuté, des paramètres différents peuvent être nécessaires.
- Un playbook peut être déclenché automatiquement à partir du worker d’alertes, ou manuellement via une route API.

#### Exigences techniques

- Module `playbook` indépendant et réutilisable.
- Exécution synchrone ou asynchrone selon le type de playbook.
- Journalisation des exécutions dans la base de données.
- Prise en charge de plusieurs types :
  - blocage d’IP ;
  - désactivation de compte ;
  - isolation de machine ;
  - escalade d’incident ;
  - collecte de traces forensiques.

#### Routes backend attendues

- `GET /api/v1/playbooks`
- `GET /api/v1/playbooks/{id}`
- `POST /api/v1/playbooks/{id}/execute`

#### Paramètres d’exécution

Le endpoint doit accepter un payload configurable selon le playbook :

- `reason`
- `target_ip`
- `target_user`
- `host`
- `severity`
- `alert_id`
- `correlation_rule_id`

---

### 2.5 UEBA

#### Besoin métier

Le backend doit permettre :

- le lancement manuel du worker UEBA ;
- l’obtention des profils UEBA actuels ;
- l’automatisation périodique du traitement, notamment tous les 30 jours.

#### Exigences techniques

- Worker UEBA indépendant, tournant en boucle ou par planification.
- Calcul des profils à partir des données historiques et comportementales.
- Stockage des profils dans PostgreSQL (`ueba_profiles`).
- Les profils historiques peuvent être conservés dans Elasticsearch si nécessaire.

#### Routes backend attendues

- `GET /api/v1/ueba/profiles`
- `POST /api/v1/ueba/run`

---

### 2.6 Rapports

#### Besoin métier

Le backend doit générer des rapports détaillés sur les activités du SIEM de façon périodique, avec un niveau de précision élevé.

#### Contenu attendu du rapport

Un rapport doit contenir au minimum :

- alertes détectées ;
- activités suspectes ;
- comptes suspects ;
- adresses IP suspectes ;
- profils UEBA actuels depuis PostgreSQL ;
- profils UEBA historique depuis Elasticsearch si nécessaire ;
- tendances de corrélation et règles déclenchées.

#### Exigences techniques

- Génération automatique hebdomadaire.
- Génération manuelle sur une période donnée.
- Stockage dans PostgreSQL.
- API CRUD sur les rapports.

#### Routes backend attendues

- `GET /api/v1/reports`
- `GET /api/v1/reports/{id}`
- `POST /api/v1/reports/generate`
- `PATCH /api/v1/reports/{id}`
- `DELETE /api/v1/reports/{id}`

---

## 3. Architecture backend recommandée

### 3.1 Structure modulaire

Le backend doit être organisé par modules métier, avec séparation claire entre :

- `app/auth/` : authentification, JWT, MFA TOTP ;
- `app/alerts/` : gestion des alertes et enrichissement ;
- `app/logs/` : recherche et consultation des logs Elasticsearch ;
- `app/correlation_rules/` : règles de corrélation ;
- `app/playbook/` : exécution de playbooks ;
- `app/ueba_profile/` : profils UEBA ;
- `app/reports/` : génération et stockage des rapports ;
- `app/audit_logs/` : journalisation immuable ;
- `app/workers/` : workers de fond ;
- `app/core/` : services communs (DB, Elasticsearch, Redis, RBAC, sécurité, audit).

### 3.2 Couche de service

Chaque module doit respecter cette séparation :

- `controller.py` : endpoints FastAPI ;
- `models.py` : schémas Pydantic ;
- `services.py` : logique métier ;
- `__init__.py` : export du router du module.

### 3.3 Couche de données

- PostgreSQL : utilisé pour les données métier structurées.
- Elasticsearch : utilisé pour la recherche et l’historique des logs.
- Redis : utilisé pour la file d’attente, le cache, et éventuellement la coordination des workers.

---

## 4. Exigences techniques détaillées

### 4.1 Workers

Le système doit contenir au minimum trois workers métier :

1. `alert_worker` :
   - surveille la table `alerts` ;
   - détecte les alertes actives ;
   - déclenche le playbook approprié.

2. `ueba_worker` :
   - analyse les profils comportementaux ;
   - écrit les résultats dans `ueba_profiles` ;
   - peut être déclenché manuellement ou de façon périodique.

3. `report_worker` :
   - génère automatiquement des rapports hebdomadaires ;
   - enregistre les rapports dans PostgreSQL.

### 4.2 Recherche modulaire

Toutes les routes de lecture doivent supporter des paramètres de filtrage optionnels. La logique doit être la suivante :

- si un paramètre est présent, il est utilisé ;
- s’il est absent, il est ignoré ;
- il ne doit pas provoquer d’erreur de validation ni d’échec de requête.

### 4.3 Authentification et sécurité

Le backend doit intégrer :

- JWT pour l’authentification ;
- MFA TOTP pour l’accès sensible ;
- RBAC centralisé ;
- journalisation des actions sensibles ;
- contrôle des permissions au niveau des routes.

### 4.4 RBAC

Le système doit définir clairement les rôles suivants :

- `lecteur`
- `analyste`
- `administrateur`
- `auditeur`

Permissions attendues :

- lecture des alertes, logs, rapports, profils UEBA ;
- exécution de playbooks ;
- gestion des règles de corrélation ;
- administration des utilisateurs et des droits.

---

## 5. Dépendances techniques attendues

### Backend

- FastAPI
- Pydantic v2
- Uvicorn
- asyncpg ou SQLAlchemy async
- Elasticsearch Python client
- Redis Python client
- PyOTP
- python-jose
- bcrypt
- slowapi

### Orchestration

- APScheduler ou Celery Beat selon la complexité retenue.

### Base de données

- PostgreSQL avec les tables métiers suivantes :
  - `alerts`
  - `ueba_profiles`
  - `correlation_rules`
  - `playbook_executions`
  - `reports`
  - `users`
  - `audit_logs`

### Recherche

- Elasticsearch avec indices `siems-logs-*`.

---

## 6. Exigences de qualité

- Le backend doit être modulaire et testé par module.
- Chaque route doit être sécurisée par RBAC.
- Les workers doivent être isolés de l’API et pouvoir tourner indépendamment.
- Les interfaces entre PostgreSQL et Elasticsearch doivent être clairement encapsulées dans les services.
- Les erreurs doivent être journalisées et propagées proprement.
- Les requêtes de recherche doivent rester performantes même avec un volume élevé de logs.

---

## 7. Livrables attendus

1. Modules FastAPI par domaine métier.
2. Routes CRUD et routes de recherche filtrée.
3. Workers automatiques pour alertes, UEBA et rapports.
4. Intégration PostgreSQL + Elasticsearch + Redis.
5. Contrôle d’accès RBAC.
6. Documentation d’API et structure de code claire.

---

## 8. Priorisation recommandée

### Priorité 1

- routes alertes ;
- routes logs ;
- module playbook ;
- RBAC de base.

### Priorité 2

- workers alertes ;
- route détail d’alerte enrichie ;
- routes correlation rules.

### Priorité 3

- UEBA worker et routes profils ;
- génération de rapports ;
- intégration complète des workers périodiques.
