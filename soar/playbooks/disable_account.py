"""
soar/playbooks/disable_account.py — Playbook SOAR de désactivation de compte

Responsable : Module SOAR — Réponse automatisée
Exigences   : RF-SOAR-03 (désactivation compte), NFR-SEC-03 (audit trail)
MITRE ATT&CK: T1078 (Valid Accounts), T1110 (Brute Force), T1068 (Privilege Escalation)

Ce playbook désactive un compte utilisateur détecté dans une alerte SOAR.
Il opère exclusivement via l'API Elasticsearch (index idx-users) sans
modifier les systèmes d'authentification externes (AD, LDAP).

Protections strictes :
  - Liste des comptes système jamais désactivables (admin, root, elastic…)
  - Vérification que l'utilisateur existe bien dans le SIEM avant toute action
  - Politique SOAR complète (kill-switch, approbation, rate-limit)
  - Mode dry-run activé par défaut
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import logging     # Journalisation structurée
import os          # Variables d'environnement
from typing import Any, Dict, Optional  # Annotations de types

# ─────────────────────────────────────────────
# Imports internes SOAR
# ─────────────────────────────────────────────
from soar.playbooks.base_playbook import BasePlaybook  # Contrat commun
from soar.policy import PROTECTED_ACCOUNTS, SoarPolicy # Politique + comptes protégés

# ─────────────────────────────────────────────
# Logger dédié au playbook
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.playbooks.disable_account")


class DisableAccountPlaybook(BasePlaybook):
    """
    Désactive un compte SIEM après approbation et validation de sévérité.

    Ce playbook modifie le champ `is_active=False` dans idx-users.
    Il ne modifie PAS les systèmes externes (Active Directory, LDAP, Okta).
    Pour une intégration AD/LDAP, un connecteur dédié doit être développé.

    Cycle d'exécution
    -----------------
    1. Extraction du nom d'utilisateur depuis l'alerte
    2. Vérification que le compte n'est pas un compte système protégé
    3. Décision de la politique SOAR
    4. Recherche de l'utilisateur dans Elasticsearch
    5. Désactivation du compte (dry-run ou réelle)
    """

    # ── Identité du playbook ────────────────────────────────────────────────
    name = "disable_account"      # Nom unique dans le registre de l'executor
    destructive = True            # Modifie l'état d'un utilisateur dans la base
    mitre_technique = "T1078"     # Valid Accounts — l'attaquant exploite un compte valide
    mitre_tactic = "Defense Evasion / Initial Access"

    def __init__(self, es: Any, policy: SoarPolicy | None = None) -> None:
        """
        Initialise le playbook avec un client Elasticsearch et une politique SOAR.

        Paramètres
        ----------
        es     : Client AsyncElasticsearch (injecté par l'executor).
                 Séparation des responsabilités : le playbook ne crée pas
                 ses propres connexions à la base de données.
        policy : Politique SOAR. Si None, utilise les valeurs d'environnement.
        """
        self.es = es                       # Client Elasticsearch (DI)
        self.policy = policy or SoarPolicy()  # Politique fail-closed

    # ─────────────────────────────────────────
    # Extraction du nom d'utilisateur
    # ─────────────────────────────────────────

    def _extract_username(self, alert: Dict[str, Any]) -> Optional[str]:
        """
        Extrait le nom d'utilisateur cible depuis l'alerte SOAR.

        Cherche dans plusieurs champs dans l'ordre de priorité :
        1. Champ direct `username`
        2. Champs normalisés `normalized_fields.username`
        3. Contexte UEBA `ueba_context.entity_id`

        Retourne None si aucun nom valide n'est trouvé.
        """
        candidates = [
            alert.get("username"),
            alert.get("normalized_fields", {}).get("username"),
            alert.get("ueba_context", {}).get("entity_id"),
        ]
        for c in candidates:
            if c and isinstance(c, str):
                username = c.strip().lower()   # Normalise en minuscules
                if len(username) >= 2:         # Longueur minimale de sécurité
                    return username
        return None

    # ─────────────────────────────────────────
    # Recherche de l'utilisateur dans ES
    # ─────────────────────────────────────────

    async def _find_user_in_es(self, username: str) -> Optional[str]:
        """
        Recherche l'utilisateur dans idx-users et retourne son _id.

        Retourne None si l'utilisateur n'existe pas dans le SIEM.
        Ne lève jamais d'exception — retourne None en cas d'erreur.
        """
        try:
            res = await self.es.search(
                index="idx-users",
                query={"term": {"username": username}},  # Correspondance exacte
                size=1,  # On ne cherche qu'un seul résultat
            )
            hits = res["hits"]["hits"]
            if hits:
                return hits[0]["_id"]   # Retourne l'ID interne Elasticsearch
            return None
        except Exception as exc:
            logger.error("[DisableAccount] Erreur recherche ES pour %r : %s", username, exc)
            return None

    # ─────────────────────────────────────────
    # Méthode principale : execute()
    # ─────────────────────────────────────────

    async def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Désactive le compte utilisateur après validation complète.

        Étapes
        ------
        1. Extraction et validation du nom d'utilisateur
        2. Protection des comptes système (liste noire absolue)
        3. Décision de la politique SOAR
        4. Vérification de l'existence dans Elasticsearch
        5. Désactivation (dry-run ou réelle)
        """
        # ── ÉTAPE 1 : Extraction de l'utilisateur ─────────────────────────
        username = self._extract_username(alert)
        if not username:
            return self.skipped(
                "Nom d'utilisateur introuvable dans l'alerte",
                target=None,
            )

        # ── ÉTAPE 2 : Protection des comptes système (absolue) ────────────
        # Cette vérification est doublée depuis la politique, mais elle est
        # répétée ici comme ligne de défense supplémentaire (défense en profondeur)
        if username in PROTECTED_ACCOUNTS:
            return self.skipped(
                f"Compte système protégé, désactivation automatique interdite : {username!r}",
                target=username,
            )

        # ── ÉTAPE 3 : Décision de la politique SOAR ───────────────────────
        decision = self.policy.decide(
            playbook=self.name,
            alert=alert,
            target=username,
        )
        if not decision.allowed:
            return self.skipped(decision.reason, target=username)

        # ── ÉTAPE 4 : Recherche dans Elasticsearch ────────────────────────
        user_id = await self._find_user_in_es(username)
        if not user_id:
            return self.skipped(
                f"Utilisateur {username!r} non trouvé dans l'index idx-users",
                target=username,
            )

        # ── ÉTAPE 5a : Mode dry-run ────────────────────────────────────────
        is_dry_run = self.policy.dry_run or os.getenv("DISABLE_ACCOUNT_DRY_RUN", "true").lower() == "true"
        if is_dry_run:
            logger.warning(
                "[DisableAccount] DRY-RUN — désactivation simulée pour %r (id=%s) decision_id=%s",
                username, user_id, decision.decision_id,
            )
            return self.success(
                target=username,
                extra={
                    "action": "disable_account",
                    "user_id": user_id,
                    "dry_run": True,
                    "decision_id": decision.decision_id,
                    "index": "idx-users",
                },
            )

        # ── ÉTAPE 5b : Désactivation réelle dans Elasticsearch ────────────
        try:
            await self.es.update(
                index="idx-users",
                id=user_id,
                doc={
                    "is_active": False,                    # Désactive le compte
                    "disabled_by": "soar",                 # Marque la source de l'action
                    "disabled_reason": f"SOAR: alerte {alert.get('rule_id', 'unknown')}",
                },
            )
            logger.info(
                "[DisableAccount] Compte désactivé par SOAR : %r (id=%s) decision_id=%s",
                username, user_id, decision.decision_id,
            )
            return self.success(
                target=username,
                extra={
                    "action": "disable_account",
                    "user_id": user_id,
                    "dry_run": False,
                    "decision_id": decision.decision_id,
                    "index": "idx-users",
                },
            )
        except Exception as exc:
            logger.error(
                "[DisableAccount] Erreur lors de la désactivation de %r : %s", username, exc
            )
            return self.failed(
                "Erreur technique lors de la désactivation du compte",
                target=username,
            )
