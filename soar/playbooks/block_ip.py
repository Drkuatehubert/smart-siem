"""
soar/playbooks/block_ip.py — Playbook SOAR de blocage IP (RF-ALR-04)

Responsable : Module SOAR — Réponse automatisée
Exigences   : RF-SOAR-02 (blocage IP automatique), NFR-SEC-03 (audit trail)
MITRE ATT&CK: T1110 (Brute Force), T1046 (Network Scanning), T1041 (Exfiltration)

Ce playbook bloque une adresse IP source détectée dans une alerte SOAR.
Il applique une règle iptables DROP après avoir :
  1. Extrait et validé l'IP de l'alerte
  2. Interrogé la politique SOAR (fail-closed)
  3. Vérifié que l'IP n'est pas dans la whitelist protégée
  4. Loggué la décision avec son identifiant HMAC

En mode dry-run (défaut), l'action est simulée sans modification du système.
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import ipaddress   # Validation et normalisation des adresses IP
import logging     # Journalisation structurée
import os          # Variables d'environnement (dry-run, whitelist)
import subprocess  # Exécution de la commande iptables
from typing import Any, Dict, FrozenSet  # Annotations de types

# ─────────────────────────────────────────────
# Imports internes SOAR
# ─────────────────────────────────────────────
from soar.playbooks.base_playbook import BasePlaybook  # Contrat commun
from soar.policy import SoarPolicy                      # Politique fail-closed

# ─────────────────────────────────────────────
# Logger dédié au playbook
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.playbooks.block_ip")

# ─────────────────────────────────────────────
# Whitelist d'IPs jamais bloquables
# ─────────────────────────────────────────────
# Ces IPs appartiennent à l'infrastructure interne critique.
# Les ajouter ici prévient tout blocage accidentel d'un faux-positif
# qui rendrait un service essentiel inaccessible.
_PROTECTED_IPS: FrozenSet[str] = frozenset(
    filter(None, os.getenv("SOAR_IP_WHITELIST", "").split(","))
) | frozenset({
    # Adresses de gestion toujours protégées
    "127.0.0.1",     # Loopback IPv4
    "::1",           # Loopback IPv6
})

# Délai maximal pour la commande iptables (prévient les blocages système)
IPTABLES_TIMEOUT_S: int = 10


class BlockIPPlaybook(BasePlaybook):
    """
    Bloque une adresse IP source via iptables après validation stricte.

    Cycle d'exécution
    -----------------
    1. Extraction de l'IP depuis l'alerte (plusieurs champs possibles)
    2. Normalisation et validation syntaxique de l'IP
    3. Vérification que l'IP n'est pas protégée (whitelist + réseaux privés)
    4. Décision de la politique SOAR (rate-limit, approbation, sévérité)
    5. Exécution (dry-run simulé OU iptables réel selon SOAR_DRY_RUN)
    6. Retour d'un résultat normalisé (success/skipped/failed)
    """

    # ── Identité du playbook ────────────────────────────────────────────────
    name = "block_ip"           # Nom unique dans le registre de l'executor
    destructive = True          # Modifie les règles réseau du système hôte
    mitre_technique = "T1110"   # Brute Force (le déclencheur le plus fréquent)
    mitre_tactic = "Defense Evasion / Impact"

    def __init__(self, policy: SoarPolicy | None = None) -> None:
        """
        Initialise le playbook avec une politique SOAR.

        Paramètres
        ----------
        policy : Instance de SoarPolicy. Si None, une instance par défaut
                 est créée (valeurs lues depuis les variables d'environnement).
        """
        # Utilise la politique fournie ou en crée une par défaut
        self.policy = policy or SoarPolicy()

    # ─────────────────────────────────────────
    # Extraction de l'IP depuis l'alerte
    # ─────────────────────────────────────────

    def _extract_ip(self, alert: Dict[str, Any]) -> str | None:
        """
        Extrait l'adresse IP source de l'alerte.

        Cherche dans plusieurs champs pour maximiser la compatibilité
        avec les différentes règles de corrélation.
        Retourne None si aucune IP valide n'est trouvée.
        """
        # Champs candidats par ordre de priorité
        candidates = [
            alert.get("source_ip"),                                     # Champ direct
            alert.get("normalized_fields", {}).get("source_ip"),        # Champ normalisé
            alert.get("ueba_context", {}).get("source_ip"),             # Contexte UEBA
        ]
        for candidate in candidates:
            if candidate and isinstance(candidate, str):
                raw = candidate.strip()
                try:
                    # Normalise l'IP (ex: "::ffff:1.2.3.4" → "1.2.3.4")
                    return str(ipaddress.ip_address(raw))
                except ValueError:
                    # Pas une IP valide, essaie le candidat suivant
                    logger.debug("Candidat IP invalide : %r", raw)
                    continue
        return None

    # ─────────────────────────────────────────
    # Vérification de la whitelist
    # ─────────────────────────────────────────

    def _is_protected(self, ip: str) -> bool:
        """
        Vérifie si une IP est dans la whitelist de protection.

        Retourne True si l'IP NE DOIT PAS être bloquée.
        """
        return ip in _PROTECTED_IPS

    # ─────────────────────────────────────────
    # Exécution réelle via iptables
    # ─────────────────────────────────────────

    def _apply_iptables_block(self, ip: str) -> None:
        """
        Applique la règle iptables DROP pour l'IP cible.

        Commande : iptables -A INPUT -s <ip> -j DROP
        Timeout  : IPTABLES_TIMEOUT_S secondes maximum

        Raises
        ------
        subprocess.CalledProcessError : Si iptables retourne un code non nul.
        subprocess.TimeoutExpired    : Si la commande dépasse le timeout.
        FileNotFoundError            : Si iptables n'est pas disponible.
        """
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(
            cmd,
            check=True,                    # Lève une exception si code != 0
            timeout=IPTABLES_TIMEOUT_S,    # Timeout strict pour éviter les blocages
            capture_output=True,           # Capture stdout/stderr (évite l'affichage)
        )

    # ─────────────────────────────────────────
    # Méthode principale : execute()
    # ─────────────────────────────────────────

    async def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exécute le blocage IP après validation complète.

        Étapes
        ------
        1. Extraction et validation de l'IP de l'alerte
        2. Vérification de la whitelist
        3. Décision de la politique SOAR
        4. Exécution (dry-run ou iptables réel)

        Retourne un dictionnaire normalisé (success / skipped / failed).
        """
        # ── ÉTAPE 1 : Extraction de l'IP ──────────────────────────────────
        ip = self._extract_ip(alert)
        if not ip:
            # Aucune IP valide trouvée → skip non-destructif
            return self.skipped(
                "Aucune adresse IP valide trouvée dans l'alerte",
                target=None,
            )

        # ── ÉTAPE 2 : Vérification de la whitelist ────────────────────────
        if self._is_protected(ip):
            return self.skipped(
                f"IP protégée par whitelist, blocage refusé : {ip}",
                target=ip,
            )

        # ── ÉTAPE 3 : Décision de la politique SOAR ───────────────────────
        # La politique vérifie : kill-switch, rate-limit, sévérité, approbation,
        # réseau privé, et génère un decision_id signé HMAC
        decision = self.policy.decide(
            playbook=self.name,
            alert=alert,
            target=ip,
        )
        if not decision.allowed:
            # La politique a refusé l'action → skip avec la raison
            return self.skipped(
                decision.reason,
                target=ip,
            )

        # ── ÉTAPE 4a : Mode dry-run (simulation) ─────────────────────────
        # SOAR_DRY_RUN=true (défaut) → log l'action sans l'exécuter
        is_dry_run = self.policy.dry_run or os.getenv("BLOCK_IP_DRY_RUN", "true").lower() == "true"
        if is_dry_run:
            logger.warning(
                "[BlockIP] DRY-RUN — blocage simulé pour IP=%s decision_id=%s",
                ip, decision.decision_id,
            )
            return self.success(
                target=ip,
                extra={
                    "action": "block_ip",
                    "dry_run": True,                         # Simulation uniquement
                    "decision_id": decision.decision_id,     # Traçabilité HMAC
                    "command": f"iptables -A INPUT -s {ip} -j DROP",  # Commande simulée
                },
            )

        # ── ÉTAPE 4b : Exécution réelle iptables ──────────────────────────
        try:
            self._apply_iptables_block(ip)
            logger.info(
                "[BlockIP] IP bloquée par SOAR : %s decision_id=%s",
                ip, decision.decision_id,
            )
            return self.success(
                target=ip,
                extra={
                    "action": "block_ip",
                    "dry_run": False,                        # Action réelle appliquée
                    "decision_id": decision.decision_id,
                    "command": f"iptables -A INPUT -s {ip} -j DROP",
                },
            )
        except subprocess.TimeoutExpired:
            # iptables a mis trop longtemps → signale un échec sans exposer de détails
            logger.error("[BlockIP] Timeout iptables pour IP=%s", ip)
            return self.failed(
                "Timeout lors de l'application de la règle iptables",
                target=ip,
            )
        except FileNotFoundError:
            # iptables n'est pas disponible dans l'environnement (ex: Windows, container)
            logger.error("[BlockIP] iptables introuvable sur ce système")
            return self.failed(
                "iptables non disponible sur ce système (container non Linux ?)",
                target=ip,
            )
        except Exception as exc:
            # Toute autre erreur système → échec générique (pas de détail technique exposé)
            logger.error("[BlockIP] Erreur lors du blocage de %s : %s", ip, exc)
            return self.failed(
                "Erreur technique lors du blocage IP — voir les logs SOAR",
                target=ip,
            )
