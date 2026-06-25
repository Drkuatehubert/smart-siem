# Guide de Connexion Étape par Étape : Bases de Données Distantes (Elasticsearch, PostgreSQL) et Agents SIEM

Ce guide explique comment configurer les connexions réseau sécurisées entre les composants du Smart SIEM et des services (Elasticsearch, PostgreSQL) ou agents (Filebeat, Syslog) hébergés sur des **machines distinctes (distantes)**. 

Puisque le Frontend et le Backend sont en cours de développement et appelés à être modifiés, ce guide établit les architectures et conventions de sécurité à respecter lors de ces futures modifications.

---

## 1. Schéma d'Architecture Cible

Dans un environnement de production multi-machines, le flux des communications se présente ainsi :

```mermaid
graph TD
    subgraph Machine Client (Agent)
        A[Agent : Filebeat / Winlogbeat]
    end

    subgraph Machine SIEM (Backend, SOAR, Frontend)
        B[Backend API]
        C[Moteur SOAR / UEBA]
        D[Collecteur / Logstash]
    end

    subgraph Machine Elasticsearch
        E[(Elasticsearch Cluster)]
    end

    subgraph Machine Database
        F[(PostgreSQL Database)]
    end

    A -- "Logstash Protocol (TLS 5044 / mTLS)" --> D
    D -- "HTTPS TLS (9200)" --> E
    B -- "HTTPS TLS (9200)" --> E
    C -- "HTTPS TLS (9200)" --> E
    B -- "pgSSL (5432 / verify-full)" --> F
```

---

## 2. Étape 1 : Connexion Réseau Sécurisée à PostgreSQL Distant

PostgreSQL stocke les données utilisateurs et la configuration de l'application. Lorsqu'il est délocalisé sur une machine B :

### A. Configuration du Serveur PostgreSQL Distant
Sur la machine hôte de PostgreSQL, modifiez les fichiers de configuration :
1. **`postgresql.conf`** : Autoriser l'écoute sur l'adresse IP réseau (ne pas limiter à `localhost`).
   ```ini
   listen_addresses = '*'
   ```
2. **Activer le TLS (SSL) dans `postgresql.conf`** :
   ```ini
   ssl = on
   ssl_cert_file = '/var/lib/postgresql/certs/server.crt'
   ssl_key_file = '/var/lib/postgresql/certs/server.key'
   ssl_ca_file = '/var/lib/postgresql/certs/ca.crt'
   ```
3. **`pg_hba.conf`** : Forcer la connexion chiffrée SSL pour le sous-réseau du Backend SIEM.
   ```text
   # Type   Database        User            Address                 Method
   hostssl  smart_siem_db   siem_user       192.168.1.10/32         scram-sha-256 clientcert=verify-full
   ```

### B. Configuration du Backend SIEM (Variables d'Environnement)
Lors du développement ou de la modification du Backend, ne mettez jamais de credentials ou d'IPs en dur. Remplissez le fichier `.env` du Backend :
```bash
# Configuration de la base de données distante
POSTGRES_HOST=192.168.1.20              # IP de la machine PostgreSQL
POSTGRES_PORT=5432
POSTGRES_DB=smart_siem_db
POSTGRES_USER=siem_user
POSTGRES_PASSWORD=SecretComplexPasswordHere

# Mode SSL PostgreSQL (verify-full exige la validation du certificat du serveur et du client)
POSTGRES_SSL_MODE=verify-full
POSTGRES_SSL_CA_CERT=/app/certs/ca.crt
POSTGRES_SSL_CLIENT_CERT=/app/certs/client_backend.crt
POSTGRES_SSL_CLIENT_KEY=/app/certs/client_backend.key
```

---

## 3. Étape 2 : Connexion Réseau Sécurisée à Elasticsearch Distant

Elasticsearch stocke les journaux d'audit, les alertes, les exécutions du SOAR et les événements UEBA.

### A. Configuration du Serveur Elasticsearch Distant
Sur la machine Elasticsearch, dans `/etc/elasticsearch/elasticsearch.yml` :
1. **Réseau** : Autoriser l'écoute sur l'IP réseau.
   ```yaml
   network.host: 192.168.1.30
   http.port: 9200
   ```
2. **Sécurité & Certificats** : Forcez l'HTTPS et configurez les certificats générés par la PKI.
   ```yaml
   xpack.security.enabled: true
   xpack.security.http.ssl:
     enabled: true
     key: certs/elasticsearch.key
     certificate: certs/elasticsearch.crt
     certificate_authorities: [ "certs/ca.crt" ]
   ```

### B. Configuration du SIEM (Backend, Moteur de Corrélation, UEBA, SOAR)
Tous ces modules utilisent le client `AsyncElasticsearch` configuré dans `app/core/elasticsearch.py` ou `correlation/engine.py`. Ils doivent charger les variables suivantes du `.env` :
```bash
ELASTICSEARCH_HOST=https://192.168.1.30:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=ElasticPasswordSecure
ELASTICSEARCH_TLS_VERIFY=true
ELASTICSEARCH_CA_CERTS=/app/certs/ca.crt  # Certificat racine CA pour valider le serveur
```

---

## 4. Étape 3 : Connexion des Agents Distants (Filebeat / Syslog)

Les agents résident sur les machines clientes et collectent les logs pour les envoyer au collecteur SIEM.

### A. Protocole Agents -> SIEM Collecteur (Mutual TLS - mTLS)
Pour empêcher les faux agents d'injecter des données dans le SIEM, le collecteur (Logstash ou conteneur syslog) et l'agent doivent s'authentifier mutuellement.

#### Configuration de l'Agent Distant (ex: `filebeat.yml` sur une machine client) :
```yaml
filebeat.inputs:
  - type: filestream
    id: system-logs
    paths:
      - /var/log/auth.log
      - /var/log/syslog

output.logstash:
  hosts: ["https://siem-collector.company.lan:5044"]
  ssl.supported_protocols: [TLSv1.2, TLSv1.3]
  # Validation du certificat du SIEM
  ssl.certificate_authorities: ["/etc/filebeat/certs/ca.crt"]
  # Certificat client de l'agent pour s'identifier auprès du SIEM
  ssl.certificate: "/etc/filebeat/certs/client_agent.crt"
  ssl.key: "/etc/filebeat/certs/client_agent.key"
```

---

## 5. Directives pour le Futur Développement (Frontend & Backend)

Puisque le Frontend et le Backend seront modifiés, l'équipe de développement doit suivre les consignes de sécurité suivantes :

### A. Flux de Données et Ségrégation (Pas de connexion directe du Frontend)
- ⚠️ **Règle Absolue** : Le Frontend ne doit **JAMAIS** se connecter directement à PostgreSQL ou à Elasticsearch.
- Toute requête SQL ou de recherche d'alertes doit passer par des endpoints sécurisés du **Backend API** (FastAPI).
- Le Frontend interroge uniquement le Backend via des requêtes HTTPS sécurisées avec authentification par token JWT.

### B. Gestion Dynamique des Certificats et Rotation
- Le code du Backend et des moteurs de détection doit s'assurer que les connexions TLS supportent le rechargement de certificat sans redémarrage du processus (rotation des certificats de la PKI).
- L'utilisation de bibliothèques clientes Elasticsearch ou de pilotes PostgreSQL (comme `asyncpg` ou `psycopg2`) doit toujours passer par un constructeur de contexte SSL standardisé (`ssl.SSLContext`), similaire à la logique implémentée dans [`soar/tls_client.py`](file:///c:/Users/huber/Downloads/X3/Projet%20Integrateur/Smart%20siem/soar/tls_client.py).

### C. Validation Réseau et Pare-Feu
Avant la mise en production des machines distantes, vérifiez l'ouverture des ports à l'aide de commandes de test réseau depuis la machine SIEM :
```bash
# Vérifier la connectivité PostgreSQL
nc -zv 192.168.1.20 5432

# Vérifier la connectivité Elasticsearch
curl --cacert /app/certs/ca.crt -u elastic:ElasticPasswordSecure https://192.168.1.30:9200
```
