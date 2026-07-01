#!/bin/bash
# generate-certs.sh — Génère les certificats TLS auto-signés pour le dev
set -e
CERTS_DIR="$(dirname "$0")"
echo "Génération des certificats TLS..."
# CA
openssl genrsa -out "$CERTS_DIR/ca.key" 4096
openssl req -new -x509 -days 1826 -key "$CERTS_DIR/ca.key" -out "$CERTS_DIR/ca.pem" -subj "/CN=SmartSIEM-CA"
# Nginx
openssl genrsa -out "$CERTS_DIR/../nginx/ssl/key.pem" 2048
openssl req -new -key "$CERTS_DIR/../nginx/ssl/key.pem" -out /tmp/nginx.csr -subj "/CN=siem.local"
openssl x509 -req -days 365 -in /tmp/nginx.csr -CA "$CERTS_DIR/ca.pem" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/../nginx/ssl/cert.pem"
# Syslog TLS
openssl genrsa -out "$CERTS_DIR/syslog-server.key" 2048
openssl req -new -key "$CERTS_DIR/syslog-server.key" -out /tmp/syslog.csr -subj "/CN=syslog.siem.local"
openssl x509 -req -days 365 -in /tmp/syslog.csr -CA "$CERTS_DIR/ca.pem" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/syslog-server.crt"
# Elasticsearch HTTP TLS
openssl genrsa -out "$CERTS_DIR/elasticsearch.key" 2048
openssl req -new -key "$CERTS_DIR/elasticsearch.key" -out /tmp/elasticsearch.csr -subj "/CN=elasticsearch"
openssl x509 -req -days 365 -in /tmp/elasticsearch.csr -CA "$CERTS_DIR/ca.pem" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/elasticsearch.crt"
# Redis TLS
openssl genrsa -out "$CERTS_DIR/redis.key" 2048
openssl req -new -key "$CERTS_DIR/redis.key" -out /tmp/redis.csr -subj "/CN=redis"
openssl x509 -req -days 365 -in /tmp/redis.csr -CA "$CERTS_DIR/ca.pem" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/redis.crt"
echo "? Certificats générés dans $CERTS_DIR"
