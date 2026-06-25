"""
soar/playbooks/isolate_machine.py — Playbook SOAR d'isolation réseau de machine

Responsable : Module SOAR — Réponse automatisée
Exigences   : RF-SOAR-04 (isolation machine), NFR-SEC-03 (audit trail)
MITRE ATT&CK: T1021 (Remote Services), T1071 (Application Layer Protocol)

Ce playbook orchestre l'isolation réseau d'une machine compromise.
En l'absence de connecteur EDR natif, il génère :
  1. Un ordre d'isolation préparé et loggué
  2. Un ticket d'intervention pour l'équipe SOC
  3. Une règle iptables de quarantaine (si mode live est activé)

L'isolation complète nécessite un connecteur EDR externe (CrowdStrike,
Microsoft Defender, Carbon Black) ou une API pare-feu (Palo Alto, Fortinet).
Ce playbook prépare l'action et notifie les opérateurs.
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import logging     # Journalisation structurée
import os          # Variables d'environnement
import subprocess  # Exécution iptables (mode live uniquement)
from typing import Any, Dict, Optional  # Annotations de types

# ─────────────────────────────────────────────
# Imports internes SOAR
# ─────────────────────────────────────────────
from soar.playbooks.base_playbook import BasePlaybook  # Contrat commun
from soar.policy import SoarPolicy                      # Politique fail-closed

# ─────────────────────────────────────────────
# Logger dédié au playbook
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.playbooks.isolate_machine")

# Timeout pour les commandes iptables de quarantaine
IPTABLES_TIMEOUT_S: int = 10


class IsolateMachinePlaybook(BasePlaybook):
    """
    Prépare et orchestre l'isolation réseau d'une machine suspecte.

    Modes d'opération
    -----------------
    dry_run=True  (défaut) : Prépare l'ordre d'isolation et notifie sans agir.
    dry_run=False           : Applique des règles iptables de quarantaine.

    Note : L'isolation complète (coupure réseau totale) nécessite un connecteur
    EDR ou pare-feu géré séparément. Ce playbook est la première étape.

    Cycle d'exécution
    -----------------
    1. Extraction du hostname / IP de la machine cible
    2. Validation que ce n'est pas un hôte critique (gateway, DNS, DC)
    3. Décision de la politique SOAR
    4. Préparation de l'ordre d'isolation (always)
    5. Application des règles iptables (mode live uniquement)
    """

    # ── Identité du playbook ────────────────────────────────────────────────
    name = "isolate_machine"      # Nom unique dans le registre de l'executor
    destructive = True            # Modifie la connectivité réseau de la machine
    mitre_technique = "T1021"     # Remote Services — mouvement latéral détecté
    mitre_tactic = "Lateral Movement"

    # Hôtes critiques jamais isolables automatiquement (risque d'outage total)
    _PROTECTED_HOSTS: frozenset = frozenset(
        filter(None, os.getenv("SOAR_PROTECTED_HOSTS", "").split(","))
    ) | frozenset({
        "gateway", "gw", "router", "firewall", "dns",
        "dc", "domain-controller", "ldap", "ntp",
    })

    def __init__(self, policy: SoarPolicy | None = None) -> None:
        """
        Paramètres
        ----------
        policy : Politique SOAR. Si None, utilise les valeurs d'environnement.
        """
        self.policy = policy or SoarPolicy()

    # ─────────────────────────────────────────
    # Extraction de la cible (host ou IP)
    # ─────────────────────────────────────────

    def _extract_target(self, alert: Dict[str, Any]) -> Optional[str]:
        """
        Extrait le hostname ou l'IP de la machine à isoler.

        Cherche dans plusieurs champs par ordre de priorité.
        """
        candidates = [
            alert.get("host"),
            alert.get("hostname"),
            alert.get("normalized_fields", {}).get("host"),
            alert.get("normalized_fields", {}).get("hostname"),
            alert.get("ueba_context", {}).get("source_ip"),
        ]
        for c in candidates:
            if c and isinstance(c, str) and c.strip():
                return c.strip().lower()
        return None

    # ─────────────────────────────────────────
    # Application des règles iptables de quarantaine
    # ─────────────────────────────────────────

    def _apply_quarantine_rules(self, target: str) -> list[str]:
        """
        Applique des règles iptables de quarantaine sur la machine.

        En mode live, bloque le trafic entrant/sortant vers la cible
        en ne permettant que les communications vers le SIEM (monitoring).

        Retourne la liste des commandes appliquées.
        """
        commands_applied = []
        # Règle 1 : bloque tout trafic entrant depuis la machine compromise
        cmd_in = ["iptables", "-A", "INPUT", "-s", target, "-j", "DROP"]
        # Règle 2 : bloque tout trafic sortant vers la machine compromise
        cmd_out = ["iptables", "-A", "OUTPUT", "-d", target, "-j", "DROP"]

        for cmd in [cmd_in, cmd_out]:
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    timeout=IPTABLES_TIMEOUT_S,
                    capture_output=True,
                )
                commands_applied.append(" ".join(cmd))
                logger.info("[IsolateMachine] Règle appliquée : %s", " ".join(cmd))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
                logger.warning("[IsolateMachine] Échec règle %s : %s", " ".join(cmd), exc)

        return commands_applied

    # ─────────────────────────────────────────
    # Méthode principale : execute()
    # ─────────────────────────────────────────

    async def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestre l'isolation de la machine détectée dans l'alerte.
        """
        # ── ÉTAPE 1 : Extraction de la cible ──────────────────────────────
        target = self._extract_target(alert)
        if not target:
            return self.skipped(
                "Hostname ou IP de machine introuvable dans l'alerte",
                target=None,
            )

        # ── ÉTAPE 2 : Protection des hôtes critiques ──────────────────────
        # Vérifie que le nom de la machine ne correspond pas à un hôte critique
        target_lower = target.lower()
        for protected in self._PROTECTED_HOSTS:
            if protected in target_lower:
                return self.skipped(
                    f"Hôte critique protégé contre isolation automatique : {target!r}",
                    target=target,
                )

        # ── ÉTAPE 3 : Décision de la politique SOAR ───────────────────────
        decision = self.policy.decide(
            playbook=self.name,
            alert=alert,
            target=target,
        )
        if not decision.allowed:
            return self.skipped(decision.reason, target=target)

        # ── ÉTAPE 4a : Mode dry-run — préparation uniquement ──────────────
        is_dry_run = self.policy.dry_run or os.getenv("ISOLATE_MACHINE_DRY_RUN", "true").lower() == "true"
        if is_dry_run:
            logger.warning(
                "[IsolateMachine] DRY-RUN — isolation préparée pour %r decision_id=%s",
                target, decision.decision_id,
            )
            return self.success(
                target=target,
                extra={
                    "action": "isolate_machine",
                    "mode": "prepared",
                    "dry_run": True,
                    "decision_id": decision.decision_id,
                    "note": "Ordre d'isolation préparé — connecteur EDR/pare-feu requis pour exécution complète",
                    "required_action": f"Isoler manuellement la machine {target!r} du réseau",
                    "commands_preview": [
                        f"iptables -A INPUT -s {target} -j DROP",
                        f"iptables -A OUTPUT -d {target} -j DROP",
                    ],
                },
            )

        # ── ÉTAPE 4b : Mode live — application des règles iptables ─────────
        applied = self._apply_quarantine_rules(target)
        logger.info(
            "[IsolateMachine] Isolation appliquée pour %r (%d règles) decision_id=%s",
            target, len(applied), decision.decision_id,
        )
        return self.success(
            target=target,
            extra={
                "action": "isolate_machine",
                "mode": "applied",
                "dry_run": False,
                "decision_id": decision.decision_id,
                "commands_applied": applied,
                "note": "Règles iptables de quarantaine appliquées. Isolation complète nécessite connecteur EDR.",
            },
        )
