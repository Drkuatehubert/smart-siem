"""Pool asyncpg singleton — connexion PostgreSQL partagée par les services."""
from __future__ import annotations

import logging
import os

import asyncpg

logger = logging.getLogger("postgres")

_pool: asyncpg.Pool | None = None


async def get_pg_pool() -> asyncpg.Pool:
    """Retourne le pool de connexions, le crée au premier appel (lazy init)."""
    global _pool
    if _pool is None:
        dsn = os.environ.get(
            "PG_DSN",
            "postgresql://postgres:felicia@localhost:5432/nafeh",
        )
        _pool = await asyncpg.create_pool(
            dsn=dsn,
            min_size=2,
            max_size=10,
            command_timeout=10,
        )
        logger.info("PostgreSQL pool créé (%s)", dsn.split("@")[-1])
    return _pool


async def close_pg_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("PostgreSQL pool fermé")


async def ensure_admin_user() -> None:
    """Garantit qu'un utilisateur admin existe avec le mot de passe connu au démarrage."""
    import bcrypt
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM users WHERE username = 'admin'")
        h = bcrypt.hashpw(b"Admin123!", bcrypt.gensalt()).decode()
        if not existing:
            await conn.execute(
                """INSERT INTO users
                   (username, email, hashed_password, role, mfa_secret, mfa_enabled, is_active)
                   VALUES ('admin', 'admin@siem.local', $1, 'admin', 'JBSWY3DPEHPK3PXP', false, true)""",
                h,
            )
            logger.info("Utilisateur admin créé")
        else:
            await conn.execute(
                "UPDATE users SET hashed_password=$1, failed_login_count=0, locked_until=NULL"
                " WHERE username='admin'",
                h,
            )
            logger.info("Mot de passe admin réinitialisé")
