# Normalizer API — Smart SIEM UCAC-ICAM

Service de normalisation des logs bruts vers Elasticsearch.

## Prérequis

- Docker + Docker Compose
- Accès à une instance Elasticsearch (locale ou via ngrok)

## Configuration

```bash
cp .env.example .env
# Remplir ELASTICSEARCH_HOST, ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD
```

## Démarrage

```bash
docker-compose up -d
```

## Endpoints

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/health` | Vérifier que le service tourne |
| POST | `/normalize` | Normaliser un log unique |
| POST | `/normalize/batch` | Normaliser et indexer un lot de logs |

## Exemple — log unique

```bash
curl -k -X POST https://localhost/normalize \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-06-24T14:32:17Z",
    "message": "Failed password for invalid user admin from 192.168.1.50",
    "host": "web-server-01",
    "source": "192.168.1.50"
  }'
```

## Exemple — batch (indexe dans ES)

```bash
curl -k -X POST https://localhost/normalize/batch \
  -H "Content-Type: application/json" \
  -d '[
    {"timestamp":"2026-06-24T14:32:17Z","message":"Failed password for invalid user admin from 192.168.1.50","host":"srv-01","source":"192.168.1.50"},
    {"timestamp":"2026-06-24T14:33:00Z","message":"Accepted publickey for root from 10.0.0.5","host":"srv-02","source":"10.0.0.5"}
  ]'
```

## Arrêt

```bash
docker-compose down
```

## Environnement virtuel (développement local sans Docker)

```bash
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
python app.py
```
