"""
security.py — Gestion JWT (HS256/RS256) et hachage bcrypt

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01, NFR-SEC-02, NFR-SEC-03

Durcissements par rapport à la version initiale :
  * `jti` (UUID4) ajouté à chaque token ⇒ révocation possible via Redis ;
  * claims `iss`, `aud`, `nbf`, `type` obligatoires ⇒ blocage du token-replay
    entre environnements et de l'attaque alg="none" ;
  * `decode_access_token` exige algorithm explicit (whitelist), valide iss/aud/exp/nbf,
    applique un leeway d'horloge configurable, et refuse tout token révoqué ;
  * bcrypt tronqué silencieusement à 72 octets : on hash une fois via un helper
    qui garantit la pré-troncature explicite ;
  * `require_validated_user` re-lit l'utilisateur en ES et confirme
    `is_active` + rôle à jour ⇒ un rôle modifié invalide les tokens existants ;
  * `revoke_jti` pose un drapeau Redis avec TTL = exp - now (libération auto).
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import ExpiredSignatureError, JWTError, jwt

from app.config import settings

# Algorithmes explicitement interdits, même si un client les forge
_FORBIDDEN_ALGS = {"none", "None", "NONE", ""}

# Claims OBLIGATOIRES dans tout JWT (sinon 401)
_REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "type"]

# OAuth2 scheme — token transmis via Authorization: Bearer <token>
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ─────────────────────────────────────────────────────────────────────
# Hachage des mots de passe (bcrypt)
# ─────────────────────────────────────────────────────────────────────

# bcrypt ignore tout au-delà de 72 octets ; on tronque explicitement
_BCRYPT_MAX_BYTES = 72


def _to_bcrypt_bytes(password: str) -> bytes:
    """Encode le mot de passe en UTF-8 et tronque à 72 octets (cf. limitation bcrypt)."""
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
        return bcrypt.checkpw(
            _to_bcrypt_bytes(plain_password),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


# ─────────────────────────────────────────────────────────────────────
# Création et vérification des tokens JWT
# ─────────────────────────────────────────────────────────────────────

def _now() -> datetime:
    """Heure UTC courante (helper pour testabilité)."""
    return datetime.now(timezone.utc)


def _build_payload(
    *,
    sub: str,
    extra: Dict[str, Any],
    expires_delta: timedelta,
    token_type: str,
) -> Dict[str, Any]:
    now = _now()
    expire = now + expires_delta
    payload: Dict[str, Any] = {
        "sub": sub,
        "iat": now,
        "nbf": now,
        "exp": expire,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "jti": uuid.uuid4().hex,
        "type": token_type,
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
    payload = _build_payload(
        sub=user_id,
        extra={},
        expires_delta=timedelta(minutes=settings.JWT_REFRESH_EXPIRY_MINUTES),
        token_type="refresh",
    )
    return jwt.encode(payload, settings.API_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_mfa_token(user_id: str) -> str:
    """Jeton court (5 min)用以 porter la demande MFA en attente."""
    payload = _build_payload(
        sub=user_id,
        extra={"scope": "mfa"},
        expires_delta=timedelta(minutes=5),
        token_type="mfa",
    )
    return jwt.encode(payload, settings.API_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# ─────────────────────────────────────────────────────────────────────
# Révocation via Redis
# ─────────────────────────────────────────────────────────────────────

def _redis_sync():
    """Client Redis sync (revoke_jti est appelée depuis un endpoint async).
    On importe à la demande pour éviter de créer un client si la révocation
    n'est pas utilisée.
    """
    import redis  # type: ignore
    scheme = "rediss" if settings.REDIS_TLS else "redis"
    auth = f":{settings.REDIS_PASSWORD}@" if settings.REDIS_PASSWORD else ""
    url = f"{scheme}://{auth}{settings.REDIS_HOST}:{settings.REDIS_PORT}/0"
    return redis.Redis.from_url(url, decode_responses=True, socket_timeout=2)


def _revoked_key(jti: str) -> str:
    return f"revoked:jti:{jti}"


def revoke_jti(jti: str, exp: datetime) -> None:
    """
    Révoque un JTI jusqu'à son expiration naturelle (TTL = exp - now).
    Idempotent.
    """
    try:
        ttl = max(1, int((exp - _now()).total_seconds()))
        _redis_sync().set(_revoked_key(jti), "1", ex=ttl)
    except Exception:
        # On n'échoue pas la requête appelante si Redis est indisponible,
        # mais le logger au point d'appel est attendu.
        raise


def is_jti_revoked(jti: str) -> bool:
    """True si le JTI a été révoqué (présent dans Redis)."""
    try:
        return _redis_sync().exists(_revoked_key(jti)) > 0
    except Exception:
        # Fail-open : on accepte le token si Redis est down (refus ⇒ déni de service).
        # À权衡 ce trade-off selon le threat model.
        return False


# ─────────────────────────────────────────────────────────────────────
# Décodage et validation
# ─────────────────────────────────────────────────────────────────────

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
      * type = expected_type ("access" ou "refresh") ;
      * jti non révoqué (Redis).

    Lève HTTPException 401 sur tout échec — le message ne fuit jamais
    le détail de l'erreur interne (alg=none, signature, expiration, etc.).
    """
    # Garde-fou : on refuse explicitement tout algo interdit en plus de la whitelist pydantic
    if settings.JWT_ALGORITHM in _FORBIDDEN_ALGS:
        raise _401()

    try:
        payload = jwt.decode(
            token,
            settings.API_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            leeway=settings.JWT_ACCESS_LEEWAY_SECONDS,
            options={"require": _REQUIRED_CLAIMS, "verify_aud": True, "verify_iss": True},
        )
    except ExpiredSignatureError:
        raise _401("Token expiré")
    except JWTError:
        raise _401()

    if payload.get("type") != expected_type:
        raise _401()

    jti = payload.get("jti")
    if not jti or is_jti_revoked(jti):
        raise _401("Token révoqué")

    return payload


def decode_access_token(token: str) -> Dict[str, Any]:
    """Décode un access token (type=access)."""
    return decode_token(token, expected_type="access")


def decode_refresh_token(token: str) -> Dict[str, Any]:
    """Décode un refresh token (type=refresh)."""
    return decode_token(token, expected_type="refresh")


# ─────────────────────────────────────────────────────────────────────
# Dépendances FastAPI
# ─────────────────────────────────────────────────────────────────────

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

    Cache Redis 30 s pour éviter de marteler ES.
    """
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise _401()

    # Cache
    try:
        import json as _json
        r = _redis_sync()
        cached = r.get(f"validated_user:{user_id}")
        if cached:
            data = _json.loads(cached)
            if data.get("is_active") and data.get("role") == payload.get("role"):
                return {**payload, "_validated": True}
    except Exception:
        pass

    # Re-vérification en ES
    from app.core.elasticsearch import get_es_client  # import local pour éviter cycle
    es = get_es_client()
    try:
        doc = await es.get(index="idx-users", id=user_id)
    except Exception:
        raise _401("Utilisateur introuvable")

    src = doc["_source"]
    if not src.get("is_active", False):
        raise _401("Compte désactivé")
    if src.get("role_id") != payload.get("role"):
        # Rôle modifié : on force la déconnexion de l'ancienne session
        try:
            revoke_jti(payload["jti"], datetime.fromtimestamp(payload["exp"], tz=timezone.utc))
        except Exception:
            pass
        raise _401("Droits modifiés, veuillez vous reconnecter")

    # Mise en cache
    try:
        r = _redis_sync()
        r.set(
            f"validated_user:{user_id}",
            _json.dumps({"is_active": True, "role": src.get("role_id")}),
            ex=30,
        )
    except Exception:
        pass

    return {**payload, "_validated": True, "org_scope": src.get("org_scope") or payload.get("org_scope")}


def new_csrf_token() -> str:
    """Génère un token opaque (utilisable pour des routes state-changing)."""
    return secrets.token_urlsafe(32)
