"""
core/database.py
Gère le pool de connexions asyncpg.
CRITIQUE : inject_rls_context() DOIT être appelé avant toute query
           pour que les politiques RLS de 03_rbac.sql fonctionnent.
"""
import asyncpg
from app.config import settings
from app.core.rbac import CurrentUser

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            dsn=settings.POSTGRES_DSN,
            min_size=5,
            max_size=20,
            # L'utilisateur de connexion = siem_app_user (03_rbac.sql)
            # Il peut ensuite prendre n'importe quel rôle via SET LOCAL ROLE
        )
    return _pool


async def inject_rls_context(
    conn: asyncpg.Connection,
    user: CurrentUser
) -> None:
    """
    Injecte les variables de session PostgreSQL nécessaires aux politiques RLS.
    Ces variables sont lues par les USING(...) dans 03_rbac.sql :
      - current_setting('app.user_id', TRUE)
      - current_setting('app.user_org_scope', TRUE)
      - current_setting('app.user_role', TRUE)

    TRUE = local à la transaction → reset automatique à la fin.
    """
    await conn.execute(
        "SELECT set_config('app.user_id', $1, TRUE)", str(user.user_id)
    )
    await conn.execute(
        "SELECT set_config('app.user_org_scope', $1, TRUE)",
        user.org_scope or ""
    )
    await conn.execute(
        "SELECT set_config('app.user_role', $1, TRUE)", user.role.value
    )
    # Active le rôle SQL correspondant → les GRANTs de 03_rbac.sql s'appliquent
    await conn.execute(f"SET LOCAL ROLE siem_{user.role.value}")


class DBSession:
    """
    Context manager : ouvre une connexion, injecte le contexte RLS,
    exécute les queries, libère la connexion.
    Usage :
        async with DBSession(user) as conn:
            rows = await conn.fetch("SELECT * FROM alerts")
    """
    def __init__(self, user: CurrentUser):
        self.user = user
        self.conn: asyncpg.Connection | None = None

    async def __aenter__(self) -> asyncpg.Connection:
        pool = await get_pool()
        self.conn = await pool.acquire()
        async with self.conn.transaction():
            await inject_rls_context(self.conn, self.user)
        return self.conn

    async def __aexit__(self, *args):
        pool = await get_pool()
        await pool.release(self.conn)