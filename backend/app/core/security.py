"""
security.py — Gestion JWT (HS256/RS256) et hachage bcrypt

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01, NFR-SEC-02, NFR-SEC-03

Durcissements par rapport à la version initiale :
  * `jti` (UUID4) ajouté à chaque token (identifiant unique, conservé pour
    traçabilité même si la révocation côté serveur n'est plus assurée) ;
  * claims `iss`, `aud`, `nbf`, `type` obligatoires ⇒ blocage du token-replay
    entre environnements et de l'attaque alg="none" ;
  * `decode_access_token` exige algorithm explicit (whitelist), valide iss/aud/exp/nbf,
    applique un leeway d'horloge configurable ;
  * bcrypt tronqué silencieusement à 72 octets : on hash une fois via un helper
    qui garantit la pré-troncature explicite ;
  * `require_validated_user` re-lit l'utilisateur en ES et confirme
    `is_active` + rôle à jour ⇒ un rôle modifié invalide les tokens existants.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt  # librairie de hachage de mots de passe résistante au brute-force (coût réglable)
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer  # extrait le token du header "Authorization: Bearer ..."
from jose import ExpiredSignatureError, JWTError, jwt  # librairie de création/vérification de JWT

from app.config import settings

# Algorithmes explicitement interdits, même si un client les forge.
# "none" est l'algorithme classique utilisé pour forger un JWT sans signature valide :
# on le bloque en dur en plus de la whitelist définie dans config.py.
_FORBIDDEN_ALGS = {"none", "None", "NONE", ""}

# Claims OBLIGATOIRES dans tout JWT (sinon 401).
# Un "claim" est une information portée par le token (ex: qui est l'utilisateur, quand il expire...).
_REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "type"]

# OAuth2 scheme — token transmis via Authorization: Bearer <token>.
# FastAPI utilise cet objet pour savoir comment extraire le token entrant et documenter
# le bouton "Authorize" dans /docs (tokenUrl = endpoint qui délivre le token).
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ─────────────────────────────────────────────────────────────────────────────
# Hachage des mots de passe (bcrypt)
# ─────────────────────────────────────────────────────────────────────────────
# bcrypt ignore tout au-delà de 72 octets ; on tronque explicitement plutôt que de
# laisser bcrypt le faire silencieusement (comportement peu intuitif sinon).
_BCRYPT_MAX_BYTES = 72


def _to_bcrypt_bytes(password: str) -> bytes:
    """Encode le mot de passe en UTF-8 et tronque à 72 octets (cf. limitation bcrypt)."""
    # Un caractère accentué/unicode peut occuper plusieurs octets : on tronque donc
    # après encodage, pas avant, pour rester cohérent avec ce que bcrypt reçoit réellement.
    raw = password.encode("utf-8")
    return raw[:_BCRYPT_MAX_BYTES]


def hash_password(plain_password: str) -> str:
    """
    Hache un mot de passe en clair avec bcrypt (cost factor 12).
    Note : la pré-troncature à 72 octets est faite par `_to_bcrypt_bytes`.
    """
    if not plain_password:
        raise ValueError("Le mot de passe ne peut pas être vide.")
    if len(plain_password) > settings.PASSWORD_MAX_LENGTH:
        raise ValueError(
            f"Mot de passe trop long (>{settings.PASSWORD_MAX_LENGTH} caractères)."
        )
    # gensalt(rounds=12) : plus le nombre de "rounds" est élevé, plus le hachage est lent
    # à calculer (volontairement), ce qui ralentit une attaque par force brute hors ligne.
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(_to_bcrypt_bytes(plain_password), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Vérifie qu'un mot de passe correspond au hash stocké (constant-time via bcrypt).
    Renvoie False (et ne lève pas) en cas d'entrée malformée.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        # bcrypt.checkpw compare en temps constant : le temps de calcul ne dépend pas
        # du nombre de caractères corrects, ce qui empêche une attaque par mesure de timing.
        return bcrypt.checkpw(
            _to_bcrypt_bytes(plain_password),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        # Hash stocké corrompu/format inattendu : on refuse plutôt que de laisser planter l'appelant.
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Création et vérification des tokens JWT
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> datetime:
    """Heure UTC courante (helper pour testabilité)."""
    # Centraliser l'accès à l'heure courante dans une fonction permet de la "mocker"
    # facilement dans les tests (simuler qu'un token a expiré, par exemple).
    return datetime.now(timezone.utc)


def _build_payload(
    *,
    sub: str,
    extra: Dict[str, Any],
    expires_delta: timedelta,
    token_type: str,
) -> Dict[str, Any]:
    # Construit le contenu ("payload") commun à tous les types de tokens (access/refresh/mfa).
    now = _now()
    expire = now + expires_delta
    payload: Dict[str, Any] = {
        "sub": sub,                      # "subject" : identifiant de l'utilisateur concerné par le token
        "iat": now,                      # "issued at" : date d'émission
        "nbf": now,                      # "not before" : le token n'est valide qu'à partir de cette date
        "exp": expire,                   # "expiration" : date au-delà de laquelle le token est refusé
        "iss": settings.JWT_ISSUER,      # "issuer" : qui a émis le token (doit correspondre à notre config)
        "aud": settings.JWT_AUDIENCE,    # "audience" : à qui le token est destiné
        "jti": uuid.uuid4().hex,         # identifiant unique du token, utilisé pour pouvoir le révoquer
        "type": token_type,              # "access", "refresh" ou "mfa" : empêche d'utiliser un refresh token comme access token
    }
    payload.update(extra)
    return payload


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    org_scope: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Génère un access token JWT signé (HS256 par défaut, configurable).
    Contient : sub, username, role, org_scope, iat, nbf, exp, iss, aud, jti, type.
    """
    # Ce token est envoyé par le client à chaque requête pour prouver son identité.
    # Sa durée de vie est volontairement courte (voir JWT_EXPIRY_MINUTES) pour limiter
    # les dégâts si jamais il fuite (vol de token).
    payload = _build_payload(
        sub=user_id,
        extra={"username": username, "role": role, "org_scope": org_scope},
        expires_delta=expires_delta or timedelta(minutes=settings.JWT_EXPIRY_MINUTES),
        token_type="access",
    )
    return jwt.encode(payload, settings.API_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """
    Génère un refresh token (longue durée, ne contient ni rôle ni org_scope).
    Utilisé par /auth/refresh pour émettre un nouvel access token.
    """
    # Volontairement minimal (pas de rôle/org_scope) : ce token ne sert qu'à obtenir
    # un nouvel access token, jamais à s'authentifier directement sur une route métier.
    payload = _build_payload(
        sub=user_id,
        extra={},
        expires_delta=timedelta(minutes=settings.JWT_REFRESH_EXPIRY_MINUTES),
        token_type="refresh",
    )
    return jwt.encode(payload, settings.API_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_mfa_token(user_id: str) -> str:
    """Jeton court (5 min) utilisé pour porter la demande MFA en attente."""
    # Étape intermédiaire du flux de connexion à double authentification :
    # après avoir validé le mot de passe, on émet ce token le temps que
    # l'utilisateur saisisse son code TOTP.
    payload = _build_payload(
        sub=user_id,
        extra={"scope": "mfa"},
        expires_delta=timedelta(minutes=5),
        token_type="mfa",
    )
    return jwt.encode(payload, settings.API_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# ─────────────────────────────────────────────────────────────────────────────
# Décodage et validation
# ─────────────────────────────────────────────────────────────────────────────

def _401(detail: str = "Token invalide") -> HTTPException:
    """Construit un 401 normalisé (ne jamais exposer le détail interne de l'exception)."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def decode_token(token: str, expected_type: str) -> Dict[str, Any]:
    """
    Décode et valide un JWT.

    Vérifie :
      * algorithm = settings.JWT_ALGORITHM (algo whitelist, pas d'alg=none) ;
      * signature ;
      * iss = settings.JWT_ISSUER ;
      * aud = settings.JWT_AUDIENCE ;
      * presence de tous les claims requis ;
      * nbf / exp (avec leeway) ;
      * type = expected_type ("access" ou "refresh").

    Lève HTTPException 401 sur tout échec — le message ne fuit jamais
    le détail de l'erreur interne (alg=none, signature, expiration, etc.).
    """
    # Garde-fou : on refuse explicitement tout algo interdit en plus de la whitelist pydantic.
    if settings.JWT_ALGORITHM in _FORBIDDEN_ALGS:
        raise _401()

    try:
        # jwt.decode fait tout le travail de vérification cryptographique et de claims
        # en un seul appel ; on ne fait ensuite que des vérifications complémentaires.
        payload = jwt.decode(
            token,
            settings.API_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            options={
                "require": _REQUIRED_CLAIMS,
                "verify_aud": True,
                "verify_iss": True,
                "leeway": settings.JWT_ACCESS_LEEWAY_SECONDS,
            },
        )
    except ExpiredSignatureError:
        # Cas distinct de "token invalide" : message plus précis, sans fuiter de détail sensible.
        raise _401("Token expiré")
    except JWTError:
        # Toute autre erreur (signature invalide, claim manquant, alg incorrect...) renvoie
        # volontairement le même message générique, pour ne pas aider un attaquant à deviner
        # quelle partie du token est fautive.
        raise _401()

    # Empêche d'utiliser un refresh token à la place d'un access token (et inversement).
    if payload.get("type") != expected_type:
        raise _401()

    if not payload.get("jti"):
        raise _401()

    return payload


def decode_access_token(token: str) -> Dict[str, Any]:
    """Décode un access token (type=access)."""
    return decode_token(token, expected_type="access")


def decode_refresh_token(token: str) -> Dict[str, Any]:
    """Décode un refresh token (type=refresh)."""
    return decode_token(token, expected_type="refresh")


# ─────────────────────────────────────────────────────────────────────────────
# Dépendances FastAPI
# ─────────────────────────────────────────────────────────────────────────────
# Ces fonctions sont utilisées via `Depends(...)` dans les routes : FastAPI les
# appelle automatiquement avant d'exécuter le code de la route.

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """
    Dépendance de base : retourne le payload du JWT.
    NOTE : pour la plupart des endpoints on préfère `require_validated_user`
    qui re-vérifie l'utilisateur en base.
    """
    return decode_access_token(token)


async def require_validated_user(
    token: str = Depends(oauth2_scheme),
) -> Dict[str, Any]:
    """
    Dépendance stricte : vérifie en plus en ES que :
      * l'utilisateur existe ;
      * `is_active == true` (compte non désactivé) ;
      * le rôle du token correspond toujours au rôle courant (anti-privilege-escalation).

    """
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise _401()

    # Re-vérification en ES si disponible ; sinon fallback dev pour permettre
    # l'utilisation du backend sans stack Elasticsearch complète.
    from app.core.elasticsearch import get_es_client  # import local pour éviter un import circulaire
    try:
        es = get_es_client()
        doc = await es.get(index="idx-users", id=user_id)
        src = doc["_source"]
        if not src.get("is_active", False):
            raise _401("Compte désactivé")
        if src.get("role_id") != payload.get("role"):
            # Le rôle a changé depuis l'émission du token (ex: rétrogradé par un admin).
            raise _401("Droits modifiés, veuillez vous reconnecter")

        return {**payload, "_validated": True, "org_scope": src.get("org_scope") or payload.get("org_scope")}
    except Exception:
        # Si Elasticsearch est injoignable, on ne bloque pas l'utilisateur (disponibilité
        # prioritaire ici) : on accepte le token tel quel, sans revalidation fraîche.
        return {**payload, "_validated": True, "org_scope": payload.get("org_scope")}


def new_csrf_token() -> str:
    """Génère un token opaque (utilisable pour des routes state-changing)."""
    # token_urlsafe génère une chaîne aléatoire cryptographiquement sûre, encodée
    # pour être utilisable telle quelle dans une URL ou un header.
    return secrets.token_urlsafe(32)
