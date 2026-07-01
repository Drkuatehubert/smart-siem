# Documentation fichiers : TLS et durcissement reseau

## `docker/certs/generate-certs.sh`

- Genere une CA locale.
- Genere le certificat Nginx.
- Genere le certificat Syslog TLS.
- Genere les certificats Elasticsearch HTTP TLS.
- Genere les certificats Redis TLS.

## `docker/elasticsearch/elasticsearch.yml`

- Active `xpack.security.http.ssl`.
- Force TLS 1.2 et TLS 1.3.
- Charge certificat, cle privee et CA.

## `docker/redis/redis.conf`

- Desactive le port clair avec `port 0`.
- Active `tls-port 6379`.
- Charge certificat, cle privee et CA.

## `docker/nginx/nginx.conf`

- Redirige HTTP vers HTTPS.
- Desactive `server_tokens`.
- Ajoute HSTS, anti-clickjacking, anti-MIME sniffing, referrer-policy et permissions-policy.
- Force TLS 1.2/1.3.

## `docker/nginx/conf.d/api.conf`

- Route `/api/` vers le backend.
- Propage `X-Request-Id`, IP source et protocole HTTPS.

## `docker/nginx/conf.d/frontend.conf`

- Route le frontend.
- Propage les en-tetes forensiques minimaux.

## `docker-compose.yml`

- Monte les certificats dans Elasticsearch, Redis, backend, correlation, SOAR et reporting.
- Configure Elasticsearch en HTTPS.
- Configure Redis en TLS.
- Maintient SOAR en approbation stricte et dry-run par defaut.
