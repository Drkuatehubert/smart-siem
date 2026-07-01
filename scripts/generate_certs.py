"""
scripts/generate_certs.py — Générateur de certificats TLS pour Smart SIEM

Ce script génère une infrastructure PKI complète :
  1. CA racine  (smart-siem-ca)
  2. Certificat serveur Nginx/Backend  (server)
  3. Certificat Elasticsearch  (elasticsearch)
  4. Certificat Redis  (redis)
  5. Certificat Syslog TLS  (syslog)
  6. Certificat client mTLS pour SOAR  (soar-client)

Tous les certificats sont signés par la CA racine interne.
Validité : 3 ans (CA), 2 ans (serveurs), 1 an (clients).

Usage :
    python scripts/generate_certs.py
    # → Crée docker/certs/ avec tous les .crt, .key, .pem
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────────────────────────
import datetime      # Durée de validité des certificats
import ipaddress     # SAN IP (Subject Alternative Name)
import os            # Création des répertoires
from pathlib import Path  # Chemins cross-platform

# Bibliothèque cryptography — génération de clés et certificats X.509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# ─────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────

# Répertoire de sortie des certificats (monté dans les conteneurs Docker)
CERTS_DIR = Path(__file__).resolve().parent.parent / "docker" / "certs"

# Organisation et pays encodés dans le DN des certificats
ORG   = "Smart SIEM"
UNIT  = "Security Operations"
COUNTRY = "FR"
STATE   = "Ile-de-France"
LOCALITY = "Paris"

# Durées de validité
CA_DAYS     = 365 * 3   # 3 ans pour la CA racine
SERVER_DAYS = 365 * 2   # 2 ans pour les certificats serveur
CLIENT_DAYS = 365 * 1   # 1 an pour les certificats client

# Taille de clé RSA (4096 bits = niveau production)
KEY_SIZE = 4096

# Exposant public RSA (65537 est la valeur standard sécurisée)
PUBLIC_EXPONENT = 65537

# Noms DNS et IPs couverts par le certificat serveur (SAN)
SERVER_DNS_NAMES = [
    "localhost",
    "backend",
    "nginx",
    "elasticsearch",
    "redis",
    "syslog",
    "correlation",
    "soar",
    "reporting",
    "frontend",
    "smart-siem.local",
]

SERVER_IP_ADDRESSES = [
    "127.0.0.1",
    "::1",
]


# ─────────────────────────────────────────────────────────────────
# Fonctions utilitaires
# ─────────────────────────────────────────────────────────────────

def _utc_now() -> datetime.datetime:
    """Retourne l'heure UTC actuelle (timezone-aware)."""
    return datetime.datetime.now(datetime.timezone.utc)


def generate_private_key() -> rsa.RSAPrivateKey:
    """
    Génère une clé privée RSA-4096.

    RSA-4096 est choisi pour sa compatibilité universelle avec les outils
    existants (OpenSSL, Java, Python, Go). ECDSA P-384 serait plus compact
    mais RSA reste plus interopérable dans les environnements mixtes.
    """
    return rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,   # 65537 = standard, sécurisé
        key_size=KEY_SIZE,                 # 4096 bits = niveau production
    )


def save_private_key(key: rsa.RSAPrivateKey, path: Path) -> None:
    """
    Sérialise et écrit une clé privée en format PEM non chiffrée.

    Note de sécurité : en production, la clé devrait être chiffrée
    avec une passphrase (BestEncryption + passphrase) ou stockée
    dans un HSM / Vault. Pour ce déploiement Docker en dev/staging,
    on l'écrit en clair avec des permissions 600.
    """
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # Format PKCS#1
        encryption_algorithm=serialization.NoEncryption(),      # Pas de passphrase
    )
    path.write_bytes(pem)
    # Restriction des permissions (lecture seule par le propriétaire)
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass  # chmod non supporté sous Windows natif (acceptable en dev)
    print(f"  🔑 Clé privée    → {path.relative_to(CERTS_DIR.parent.parent)}")


def save_certificate(cert: x509.Certificate, path: Path) -> None:
    """Sérialise et écrit un certificat X.509 en format PEM."""
    pem = cert.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(pem)
    print(f"  📜 Certificat    → {path.relative_to(CERTS_DIR.parent.parent)}")


def build_dn(common_name: str) -> x509.Name:
    """
    Construit un Distinguished Name (DN) X.509 complet.

    Le DN identifie de façon unique l'entité dans la PKI.
    """
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE),
        x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, UNIT),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


# ─────────────────────────────────────────────────────────────────
# Génération de la CA racine
# ─────────────────────────────────────────────────────────────────

def generate_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Génère la CA (Certificate Authority) racine Smart SIEM.

    La CA est auto-signée (issuer == subject) et possède l'extension
    BasicConstraints(ca=True) qui lui permet de signer d'autres certificats.

    Retourne (ca_key, ca_cert) utilisés ensuite pour signer les certificats
    serveur et client.
    """
    print("\n[1/6] Génération de la CA racine Smart SIEM…")

    # ── Génération de la clé privée CA ────────────────────────────────────
    ca_key = generate_private_key()

    # ── Construction du certificat CA ─────────────────────────────────────
    now = _utc_now()
    ca_dn = build_dn("Smart SIEM Root CA")

    ca_cert = (
        x509.CertificateBuilder()
        # Identité du sujet (la CA elle-même)
        .subject_name(ca_dn)
        # Identité de l'émetteur (auto-signé → même DN)
        .issuer_name(ca_dn)
        # Clé publique associée
        .public_key(ca_key.public_key())
        # Numéro de série unique (entier 160 bits aléatoire)
        .serial_number(x509.random_serial_number())
        # Validité : maintenant → +3 ans
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CA_DAYS))
        # Extension : ceci est une CA (peut signer des certificats)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,  # Critical = les clients DOIVENT respecter cette extension
        )
        # Extension : usage de la clé CA (signature de certificats et de CRL)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,   # Peut signer numériquement
                key_cert_sign=True,       # Peut signer des certificats
                crl_sign=True,            # Peut signer des listes de révocation
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Extension : identifiant de clé du sujet (pour chaînage)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        # Signature avec SHA-256 (SHA-1 est obsolète depuis 2017)
        .sign(ca_key, hashes.SHA256())
    )

    return ca_key, ca_cert


# ─────────────────────────────────────────────────────────────────
# Génération d'un certificat serveur
# ─────────────────────────────────────────────────────────────────

def generate_server_cert(
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    extra_dns: list[str] | None = None,
    extra_ips: list[str] | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Génère un certificat TLS serveur signé par la CA Smart SIEM.

    Les SAN (Subject Alternative Names) incluent tous les noms DNS et IPs
    connus des services Docker pour permettre la vérification côté client.

    Paramètres
    ----------
    common_name : CN du certificat (ex: "nginx", "elasticsearch")
    ca_key      : Clé privée de la CA pour signer le certificat
    ca_cert     : Certificat de la CA (pour l'émetteur et l'AKID)
    extra_dns   : DNS supplémentaires à ajouter aux SAN
    extra_ips   : IPs supplémentaires à ajouter aux SAN
    """
    # ── Génération de la clé privée serveur ───────────────────────────────
    srv_key = generate_private_key()
    now = _utc_now()

    # ── Construction des SAN (Subject Alternative Names) ──────────────────
    # Les SAN sont obligatoires depuis RFC 2818 ; le CN seul ne suffit plus
    san_dns = [x509.DNSName(name) for name in (SERVER_DNS_NAMES + (extra_dns or []))]
    san_ips = [
        x509.IPAddress(ipaddress.ip_address(ip))
        for ip in (SERVER_IP_ADDRESSES + (extra_ips or []))
    ]

    # ── Construction du certificat serveur ────────────────────────────────
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(build_dn(common_name))
        # L'émetteur est la CA Smart SIEM
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=SERVER_DAYS))
        # Extension : NOT une CA (certificat feuille uniquement)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Extension : usage de la clé (authentification TLS serveur)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,   # Signature TLS handshake
                key_encipherment=True,    # Échange de clé RSA (TLS < 1.3)
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,      # PAS une CA
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Extension : usage étendu — authentification serveur TLS
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,  # Authentification serveur TLS
            ]),
            critical=False,
        )
        # Extension : SAN — tous les noms DNS et IPs du service
        .add_extension(
            x509.SubjectAlternativeName(san_dns + san_ips),
            critical=False,
        )
        # Extension : identifiant de clé de l'autorité (pour chaînage)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        # Signature par la CA avec SHA-256
        .sign(ca_key, hashes.SHA256())
    )

    return srv_key, srv_cert


# ─────────────────────────────────────────────────────────────────
# Génération d'un certificat client (mTLS)
# ─────────────────────────────────────────────────────────────────

def generate_client_cert(
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Génère un certificat TLS client pour l'authentification mutuelle (mTLS).

    Utilisé par le SOAR pour s'authentifier auprès d'Elasticsearch et des
    services internes sans mot de passe (le certificat fait office d'identité).

    La différence avec un certificat serveur : ExtendedKeyUsage = CLIENT_AUTH.
    """
    cli_key = generate_private_key()
    now = _utc_now()

    cli_cert = (
        x509.CertificateBuilder()
        .subject_name(build_dn(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(cli_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CLIENT_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,   # Signature lors du handshake client
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Extension : usage étendu — authentification CLIENT TLS
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,  # Authentification client TLS (mTLS)
            ]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return cli_key, cli_cert


# ─────────────────────────────────────────────────────────────────
# Sauvegarde du bundle CA (chain file)
# ─────────────────────────────────────────────────────────────────

def save_ca_bundle(ca_cert: x509.Certificate, path: Path) -> None:
    """
    Écrit le certificat CA en tant que bundle (ca-bundle.pem).

    Ce fichier est utilisé par tous les services pour vérifier les
    certificats des autres services : il suffit de faire confiance
    à la CA racine Smart SIEM.
    """
    pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(pem)
    print(f"  🏛️  Bundle CA      → {path.relative_to(CERTS_DIR.parent.parent)}")


# ─────────────────────────────────────────────────────────────────
# Point d'entrée principal
# ─────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Génère l'infrastructure PKI complète du Smart SIEM.

    Structure créée dans docker/certs/ :
      ca/
        ca.crt          — Certificat de la CA racine (public, distribué partout)
        ca.key          — Clé privée CA (CONFIDENTIELLE, 600)
        ca-bundle.pem   — Bundle PEM pour la vérification (= ca.crt)
      server/
        server.crt      — Certificat serveur Nginx/Backend
        server.key      — Clé privée serveur
      elasticsearch/
        es.crt          — Certificat Elasticsearch
        es.key          — Clé privée Elasticsearch
      redis/
        redis.crt       — Certificat Redis
        redis.key       — Clé privée Redis
      syslog/
        syslog.crt      — Certificat syslog TLS (port 6514)
        syslog.key      — Clé privée syslog
      soar-client/
        soar-client.crt — Certificat client SOAR (mTLS)
        soar-client.key — Clé privée client SOAR
    """
    print("=" * 60)
    print("  Smart SIEM — Générateur de certificats TLS")
    print("=" * 60)

    # ── Création de la structure de répertoires ───────────────────────────
    subdirs = ["ca", "server", "elasticsearch", "redis", "syslog", "soar-client"]
    for sub in subdirs:
        (CERTS_DIR / sub).mkdir(parents=True, exist_ok=True)
    print(f"\n📁 Répertoire de sortie : {CERTS_DIR}")

    # ── [1] Génération de la CA racine ────────────────────────────────────
    ca_key, ca_cert = generate_ca()
    save_private_key(ca_key,  CERTS_DIR / "ca" / "ca.key")
    save_certificate(ca_cert, CERTS_DIR / "ca" / "ca.crt")
    save_ca_bundle(ca_cert,   CERTS_DIR / "ca" / "ca-bundle.pem")

    # ── [2] Certificat serveur Nginx / Backend ─────────────────────────────
    print("\n[2/6] Génération du certificat serveur Nginx/Backend…")
    srv_key, srv_cert = generate_server_cert(
        "smart-siem-server", ca_key, ca_cert
    )
    save_private_key(srv_key,  CERTS_DIR / "server" / "server.key")
    save_certificate(srv_cert, CERTS_DIR / "server" / "server.crt")

    # ── [3] Certificat Elasticsearch ──────────────────────────────────────
    print("\n[3/6] Génération du certificat Elasticsearch…")
    es_key, es_cert = generate_server_cert(
        "elasticsearch", ca_key, ca_cert,
        extra_dns=["elasticsearch", "es"],
    )
    save_private_key(es_key,  CERTS_DIR / "elasticsearch" / "es.key")
    save_certificate(es_cert, CERTS_DIR / "elasticsearch" / "es.crt")

    # ── [4] Certificat Redis ──────────────────────────────────────────────
    print("\n[4/6] Génération du certificat Redis…")
    redis_key, redis_cert = generate_server_cert(
        "redis", ca_key, ca_cert,
        extra_dns=["redis"],
    )
    save_private_key(redis_key,  CERTS_DIR / "redis" / "redis.key")
    save_certificate(redis_cert, CERTS_DIR / "redis" / "redis.crt")

    # ── [5] Certificat Syslog TLS (port 6514) ─────────────────────────────
    print("\n[5/6] Génération du certificat Syslog TLS…")
    syslog_key, syslog_cert = generate_server_cert(
        "syslog-tls", ca_key, ca_cert,
        extra_dns=["syslog", "syslog-receiver"],
    )
    save_private_key(syslog_key,  CERTS_DIR / "syslog" / "syslog.key")
    save_certificate(syslog_cert, CERTS_DIR / "syslog" / "syslog.crt")

    # ── [6] Certificat client SOAR (mTLS) ─────────────────────────────────
    print("\n[6/6] Génération du certificat client SOAR (mTLS)…")
    cli_key, cli_cert = generate_client_cert(
        "soar-client", ca_key, ca_cert
    )
    save_private_key(cli_key,  CERTS_DIR / "soar-client" / "soar-client.key")
    save_certificate(cli_cert, CERTS_DIR / "soar-client" / "soar-client.crt")

    # ── Résumé ────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  ✅  PKI Smart SIEM générée avec succès !")
    print("=" * 60)
    print("\n📋 Fichiers générés :")
    for f in sorted(CERTS_DIR.rglob("*.*")):
        size = f.stat().st_size
        ext  = "🔑" if f.suffix == ".key" else "📜"
        print(f"  {ext} {f.relative_to(CERTS_DIR.parent.parent)}  ({size} octets)")

    print("\n⚠️  SÉCURITÉ :")
    print("  • Les fichiers *.key sont CONFIDENTIELS (permission 600)")
    print("  • Ne jamais committer les clés privées dans git")
    print("  • Ajouter docker/certs/**/*.key dans .gitignore")
    print("  • Renouveler les certificats avant expiration (voir dates ci-dessus)")

    _print_env_vars()


def _print_env_vars() -> None:
    """Affiche les variables d'environnement à configurer dans .env"""
    print("\n📝 Variables .env à configurer :")
    mapping = {
        "TLS_CA_BUNDLE":             "docker/certs/ca/ca-bundle.pem",
        "ELASTICSEARCH_CA_CERTS":    "docker/certs/ca/ca-bundle.pem",
        "SYSLOG_TLS_CERT":           "docker/certs/syslog/syslog.crt",
        "SYSLOG_TLS_KEY":            "docker/certs/syslog/syslog.key",
        "TLS_CLIENT_CERT":           "docker/certs/soar-client/soar-client.crt",
        "TLS_CLIENT_KEY":            "docker/certs/soar-client/soar-client.key",
        "NGINX_SSL_CERT":            "docker/certs/server/server.crt",
        "NGINX_SSL_KEY":             "docker/certs/server/server.key",
    }
    for var, val in mapping.items():
        print(f"  {var}={val}")


if __name__ == "__main__":
    main()
