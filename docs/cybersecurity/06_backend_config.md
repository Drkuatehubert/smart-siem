# Documentation fichiers : backend et stockage

## `backend/app/config.py`

- Ajoute `SOAR_MIN_AUTO_LEVEL`.
- Ajoute `SOAR_DRY_RUN`.
- Ajoute `REDIS_CA_CERTS`.
- En production, interdit Elasticsearch non HTTPS.
- En production, interdit Redis sans TLS.

## `backend/app/main.py`

- Corrige l'import `HTTPException` utilise par les handlers.
- Conserve CORS strict, headers de securite et request-id.
- Retourne `status=ok` quand l'API repond, tout en exposant l'etat Elasticsearch dans `dependencies`.

## `backend/app/core/security.py`

- Corrige la compatibilite `python-jose` en passant le leeway JWT dans `options`.
- Conserve les validations issuer, audience, expiration, type et JTI.

## `backend/app/core/redis_client.py`

- Utilise `rediss` quand `REDIS_TLS=true`.
- Ajoute `ssl_ca_certs` pour verifier le certificat serveur Redis.

## `scripts/init_elasticsearch.py`

- Etend `idx-soar-executions` avec `playbook`, `alert_id`, `target`, `reason`.
- Etend `idx-alerts` avec les champs SOAR et UEBA.
- Etend `idx-ueba-profiles` avec IP/hosts connus.
- Etend `idx-ueba-events` avec IP et host.
