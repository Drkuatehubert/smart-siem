"""soar/clients/ad_client.py — Client LDAP pour gérer les comptes Active Directory (ctu.local)."""
import logging

import ldap3
from ldap3 import Server, Connection, MODIFY_REPLACE, SUBTREE

from soar.config import (
    AD_HOST, AD_PORT, AD_USER, AD_PASSWORD,
    AD_BASE_DN, AD_TARGET_OU,
)

logger = logging.getLogger("soar.clients.ad_client")

# Codes userAccountControl
UAC_ENABLED  = 512   # compte normal actif
UAC_DISABLED = 514   # compte désactivé (bit 0x0002 positionné)


class ADClient:
    """Client LDAPS minimaliste pour désactiver / réactiver des comptes AD."""

    def __init__(self) -> None:
        self.host     = AD_HOST
        self.port     = AD_PORT
        self.user     = AD_USER
        self.password = AD_PASSWORD
        self.base_dn  = AD_BASE_DN
        self.target_ou = AD_TARGET_OU
        self._conn: Connection | None = None

    # ------------------------------------------------------------------
    # Connexion / déconnexion
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Ouvre une connexion LDAP (port 389)."""
        if not self.password:
            logger.error("AD_PASSWORD n'est pas défini — définir la variable d'environnement AD_PASSWORD")
            return False
        try:
            server = Server(
                self.host,
                port=self.port,
                use_ssl=False,
                connect_timeout=5,
            )
            self._conn = Connection(
                server,
                user=self.user,
                password=self.password,
                auto_bind=True,
                raise_exceptions=True,
            )
            logger.info("LDAP connecté à %s:%s en tant que %s", self.host, self.port, self.user)
            return True
        except Exception as exc:
            logger.error("Échec connexion LDAP %s:%s — %s", self.host, self.port, exc)
            self._conn = None
            return False

    def disconnect(self) -> None:
        """Ferme proprement la connexion LDAPS."""
        if self._conn and self._conn.bound:
            self._conn.unbind()
            logger.info("LDAP déconnecté de %s", self.host)
        self._conn = None

    # ------------------------------------------------------------------
    # Méthodes internes
    # ------------------------------------------------------------------

    def _find_dn(self, username: str) -> str | None:
        """Retourne le DN du compte `username` dans l'OU cible, ou None."""
        if not self._conn:
            return None
        search_filter = f"(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)})"
        self._conn.search(
            search_base=self.target_ou,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName", "userAccountControl"],
        )
        if not self._conn.entries:
            logger.warning("Compte '%s' introuvable dans %s", username, self.target_ou)
            return None
        return str(self._conn.entries[0].distinguishedName)

    def _set_uac(self, username: str, uac_value: int, action_label: str) -> dict:
        """Modifie userAccountControl et retourne un dict résultat standard."""
        if not self._conn:
            if not self.connect():
                return {"succes": False, "erreur": "Connexion LDAPS impossible"}

        dn = self._find_dn(username)
        if dn is None:
            return {"succes": False, "erreur": f"Compte '{username}' non trouvé dans l'AD"}

        try:
            self._conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [uac_value])]})
            if self._conn.result["result"] == 0:
                logger.info("Compte '%s' → %s (UAC=%d)", username, action_label, uac_value)
                return {"succes": True, "compte": username, "action": action_label}
            logger.error("Erreur LDAP sur '%s' : %s", username, self._conn.result)
            return {"succes": False, "erreur": self._conn.result.get("description", "erreur inconnue")}
        except Exception as exc:
            logger.error("Exception lors de la modification de '%s' : %s", username, exc)
            return {"succes": False, "erreur": str(exc)}

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def disable_account(self, username: str) -> dict:
        """Désactive le compte AD (userAccountControl = 514)."""
        return self._set_uac(username, UAC_DISABLED, "disabled")

    def enable_account(self, username: str) -> dict:
        """Réactive le compte AD (userAccountControl = 512)."""
        return self._set_uac(username, UAC_ENABLED, "enabled")

    def get_account_status(self, username: str) -> dict:
        """Retourne l'état actuel du compte (enabled/disabled + valeur UAC)."""
        if not self._conn:
            if not self.connect():
                return {"succes": False, "erreur": "Connexion LDAPS impossible"}

        search_filter = f"(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)})"
        try:
            self._conn.search(
                search_base=self.target_ou,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "userAccountControl"],
            )
            if not self._conn.entries:
                return {"succes": False, "erreur": f"Compte '{username}' non trouvé"}

            entry = self._conn.entries[0]
            uac   = int(entry.userAccountControl.value)
            # bit 0x0002 (2) positionné → compte désactivé
            enabled = not bool(uac & 0x0002)
            return {"username": username, "enabled": enabled, "userAccountControl": uac}
        except Exception as exc:
            logger.error("Erreur get_account_status('%s') : %s", username, exc)
            return {"succes": False, "erreur": str(exc)}

    def heartbeat(self) -> bool:
        """Vérifie que l'AD répond en tentant une connexion simple."""
        if not self.password:
            logger.warning("Heartbeat ignoré : AD_PASSWORD non défini")
            return False
        try:
            server = Server(self.host, port=self.port, use_ssl=False, connect_timeout=3)
            conn   = Connection(server, user=self.user, password=self.password, raise_exceptions=True)
            ok     = conn.bind()
            conn.unbind()
            logger.debug("Heartbeat AD : %s", "OK" if ok else "KO")
            return ok
        except Exception as exc:
            logger.warning("Heartbeat AD échoué : %s", exc)
            return False


# ------------------------------------------------------------------
# Test manuel
# ------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    client = ADClient()

    print("\n=== Heartbeat ===")
    print("AD répond :", client.heartbeat())

    if not client.connect():
        print("Impossible de se connecter à l'AD. Vérifier la config et la VM.")
        raise SystemExit(1)

    print("\n=== Statut initial ===")
    for user in ("jean", "paul"):
        print(f"  {user} →", client.get_account_status(user))

    print("\n=== Désactivation ===")
    for user in ("jean", "paul"):
        print(f"  disable {user} →", client.disable_account(user))

    print("\n=== Statut après désactivation ===")
    for user in ("jean", "paul"):
        print(f"  {user} →", client.get_account_status(user))

    print("\n=== Réactivation ===")
    for user in ("jean", "paul"):
        print(f"  enable {user} →", client.enable_account(user))

    print("\n=== Statut final ===")
    for user in ("jean", "paul"):
        print(f"  {user} →", client.get_account_status(user))

    client.disconnect()
