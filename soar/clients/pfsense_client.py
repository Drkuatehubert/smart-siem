import ipaddress
import logging
import socket

import paramiko

from soar import config

logger = logging.getLogger(__name__)


class PfSenseClient:
    def __init__(self):
        self.host = config.PFSENSE_HOST
        self.port = config.PFSENSE_PORT
        self.user = config.PFSENSE_USER
        self.password = config.PFSENSE_PASSWORD
        self._client: paramiko.SSHClient | None = None

    # ------------------------------------------------------------------ #
    # Connexion                                                            #
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            self._client = client
            logger.info("pfSense SSH connecté (%s:%s)", self.host, self.port)
            return True
        except Exception as exc:
            logger.error("pfSense connexion échouée : %s", exc)
            self._client = None
            return False

    def disconnect(self):
        if self._client:
            self._client.close()
            self._client = None
            logger.info("pfSense SSH déconnecté")

    # ------------------------------------------------------------------ #
    # Exécution de commande                                                #
    # ------------------------------------------------------------------ #

    def _exec(self, cmd: str) -> tuple[str, str]:
        if self._client is None:
            logger.warning("Connexion perdue, tentative de reconnexion")
            if not self.connect():
                raise ConnectionError("Impossible de se connecter à pfSense")

        try:
            _, stdout, stderr = self._client.exec_command(cmd, timeout=15)
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            return out, err
        except (paramiko.SSHException, socket.error) as exc:
            logger.warning("Commande échouée (%s), reconnexion : %s", cmd, exc)
            self._client = None
            if not self.connect():
                raise ConnectionError("Reconnexion impossible") from exc
            _, stdout, stderr = self._client.exec_command(cmd, timeout=15)
            return stdout.read().decode().strip(), stderr.read().decode().strip()

    # ------------------------------------------------------------------ #
    # Actions pfctl                                                        #
    # ------------------------------------------------------------------ #

    def block_ip(self, ip: str) -> dict:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"succes": False, "ip": ip, "action": "blocked", "error": "IP invalide"}

        out, err = self._exec(f"pfctl -t blocklist -T add {ip}")
        if err:
            logger.warning("block_ip stderr : %s", err)

        logger.info("IP bloquée : %s", ip)
        return {"succes": True, "ip": ip, "action": "blocked"}

    def unblock_ip(self, ip: str) -> dict:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"succes": False, "ip": ip, "action": "unblocked", "error": "IP invalide"}

        out, err = self._exec(f"pfctl -t blocklist -T delete {ip}")
        if err:
            logger.warning("unblock_ip stderr : %s", err)

        logger.info("IP débloquée : %s", ip)
        return {"succes": True, "ip": ip, "action": "unblocked"}

    def get_blocked_ips(self) -> list[str]:
        out, err = self._exec("pfctl -t blocklist -T show")
        if err:
            logger.warning("get_blocked_ips stderr : %s", err)
        if not out:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]

    # ------------------------------------------------------------------ #
    # Heartbeat                                                            #
    # ------------------------------------------------------------------ #

    def heartbeat(self) -> bool:
        try:
            if not self.connect():
                return False
            out, _ = self._exec("echo ok")
            return out.strip() == "ok"
        except Exception as exc:
            logger.error("Heartbeat pfSense échoué : %s", exc)
            return False
        finally:
            self.disconnect()


# ------------------------------------------------------------------ #
# Smoke test                                                          #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    client = PfSenseClient()

    print("=== heartbeat ===")
    print(client.heartbeat())

    client.connect()

    print("\n=== block_ip 10.0.0.99 ===")
    print(client.block_ip("10.0.0.99"))

    print("\n=== get_blocked_ips ===")
    print(client.get_blocked_ips())

    print("\n=== unblock_ip 10.0.0.99 ===")
    print(client.unblock_ip("10.0.0.99"))

    print("\n=== get_blocked_ips ===")
    print(client.get_blocked_ips())

    client.disconnect()
