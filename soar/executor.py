"""
soar/executor.py — Orchestrateur SOAR strict avec circuit-breaker et audit complet

Responsable : Module SOAR — Orchestration
Exigences   : RF-SOAR-01 (orchestration), NFR-SEC-03 (audit immutable),
              NFR-PERF-01 (performance), RF-INC-04 (journalisation)

Ce module est le point central qui relie les alertes aux playbooks :
  * Registre de playbooks signé (aucun playbook inconnu ne peut s'exécuter)
  * Circuit-breaker par playbook (désactivation temporaire si taux d'échec élevé)
  * Retry avec backoff exponentiel pour les erreurs transitoires
  * Audit complet : chaque exécution est écrite dans idx-soar-executions
  * Enchaînement automatique de playbooks (collect_forensics → action principale)
  * Injection de dépendances (ES) avec séparation des responsabilités

Principe de sécurité : tout playbook inconnu est refusé immédiatement.
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import asyncio     # Coordination des tâches asynchrones
import logging     # Journalisation structurée
import time        # Timestamps pour le circuit-breaker
from collections import defaultdict    # Compteurs d'erreurs par playbook
from datetime import datetime, timezone  # Horodatage UTC strict
from typing import Any, Dict, List, Optional, Type  # Annotations de types

# ─────────────────────────────────────────────
# Imports des playbooks SOAR
# ─────────────────────────────────────────────
from soar.playbooks.base_playbook import BasePlaybook          # Interface commune
from soar.playbooks.block_ip import BlockIPPlaybook            # Blocage IP
from soar.playbooks.collect_forensics import CollectForensicsPlaybook  # Forensique
from soar.playbooks.disable_account import DisableAccountPlaybook      # Désactivation compte
from soar.playbooks.escalate_incident import EscalateIncidentPlaybook  # Escalade
from soar.playbooks.isolate_machine import IsolateMachinePlaybook      # Isolation machine

# ─────────────────────────────────────────────
# Logger dédié à l'exécuteur SOAR
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.executor")

# ─────────────────────────────────────────────
# Registre de playbooks (liste blanche stricte)
# ─────────────────────────────────────────────
# Seuls les playbooks listés ici peuvent être exécutés.
# Toute demande d'exécution d'un nom inconnu est refusée avec une erreur.
PLAYBOOK_REGISTRY: Dict[str, Type[BasePlaybook]] = {
    "block_ip":          BlockIPPlaybook,          # RF-ALR-04 : blocage réseau
    "disable_account":   DisableAccountPlaybook,   # RF-ALR-05 : désactivation compte
    "isolate_machine":   IsolateMachinePlaybook,   # RF-ALR-06 : isolation machine
    "escalate_incident": EscalateIncidentPlaybook, # RF-INC-03 : escalade RSSI/SOC
    "collect_forensics": CollectForensicsPlaybook, # RF-INC-05 : collecte forensique
}

# Playbooks nécessitant l'injection du client Elasticsearch
_ES_REQUIRED_PLAYBOOKS: frozenset = frozenset({
    "disable_account",
    "escalate_incident",
    "collect_forensics",
})

# ─────────────────────────────────────────────
# Configuration du circuit-breaker
# ─────────────────────────────────────────────

# Seuil d'erreurs consécutives avant l'ouverture du circuit-breaker
CB_FAILURE_THRESHOLD: int = 5

# Durée d'ouverture du circuit-breaker (en secondes) avant ré-essai
CB_OPEN_WINDOW_S: int = 60

# Délai de base du retry exponentiel (en secondes)
RETRY_BACKOFF_BASE_S: float = 1.0

# Nombre maximum de tentatives de retry par exécution
MAX_RETRIES: int = 2


class _CircuitBreaker:
    """
    Implémentation simple du pattern Circuit-Breaker par playbook.

    États
    -----
    CLOSED  : Le playbook fonctionne normalement (état initial).
    OPEN    : Trop d'échecs consécutifs → le playbook est désactivé temporairement.
    HALF    : Après la fenêtre d'ouverture, un seul essai est permis.

    Ce circuit-breaker évite de bombarder un système défaillant avec des
    tentatives répétées qui augmenteraient la charge au lieu de la réduire.
    """

    def __init__(self) -> None:
        # Compteur d'échecs consécutifs par playbook
        self._failures: Dict[str, int] = defaultdict(int)
        # Timestamp de l'ouverture du circuit par playbook
        self._opened_at: Dict[str, float] = {}

    def is_open(self, playbook: str) -> bool:
        """
        Retourne True si le circuit est ouvert (playbook désactivé).

        Gère automatiquement la transition OPEN → HALF après la fenêtre.
        """
        if playbook not in self._opened_at:
            return False  # Circuit CLOSED (normal)

        elapsed = time.monotonic() - self._opened_at[playbook]
        if elapsed > CB_OPEN_WINDOW_S:
            # Fenêtre écoulée → passe en HALF (un essai permis)
            del self._opened_at[playbook]
            self._failures[playbook] = 0
            logger.info("[CircuitBreaker] Circuit HALF-OPEN pour %r", playbook)
            return False  # Autorise un essai

        return True  # Circuit toujours OPEN

    def record_failure(self, playbook: str) -> None:
        """Enregistre un échec et ouvre le circuit si le seuil est atteint."""
        self._failures[playbook] += 1
        if self._failures[playbook] >= CB_FAILURE_THRESHOLD:
            self._opened_at[playbook] = time.monotonic()
            logger.error(
                "[CircuitBreaker] Circuit OUVERT pour %r après %d échecs consécutifs",
                playbook, self._failures[playbook],
            )

    def record_success(self, playbook: str) -> None:
        """Enregistre un succès et remet le compteur à zéro."""
        if self._failures.get(playbook, 0) > 0:
            logger.info(
                "[CircuitBreaker] Circuit FERMÉ pour %r (succès après échecs)",
                playbook,
            )
        self._failures[playbook] = 0
        self._opened_at.pop(playbook, None)


# Instance partagée du circuit-breaker (singleton pour la durée de vie du process)
_circuit_breaker = _CircuitBreaker()


# ─────────────────────────────────────────────
# Écriture dans l'audit trail
# ─────────────────────────────────────────────

async def write_execution(
    es: Any,
    *,
    alert: Dict[str, Any],
    result: Dict[str, Any],
) -> None:
    """
    Écrit une trace d'exécution SOAR dans idx-soar-executions (append-only).

    Cet index est la preuve immutable de toutes les actions SOAR.
    Il ne doit jamais être modifié ou supprimé hors de la politique de rétention.

    Paramètres
    ----------
    es     : Client AsyncElasticsearch.
    alert  : L'alerte source ayant déclenché le playbook.
    result : Le résultat normalisé retourné par le playbook.
    """
    try:
        await es.index(
            index="idx-soar-executions",
            document={
                # ── Identification ──────────────────────────────────────
                "playbook": result.get("playbook"),           # Nom du playbook
                "alert_id": alert.get("id") or alert.get("_id"),  # ID de l'alerte source
                "rule_id": alert.get("rule_id"),              # Règle de corrélation
                "target": result.get("target"),               # Cible de l'action
                # ── Résultat ────────────────────────────────────────────
                "status": result.get("status"),               # success/skipped/error
                "reason": result.get("reason"),               # Raison en cas de skip/error
                "dry_run": result.get("dry_run", True),       # Simulation ou action réelle
                "destructive": result.get("destructive", False),  # Action irréversible ?
                # ── Traçabilité SOAR ─────────────────────────────────────
                "decision_id": result.get("decision_id", ""),  # ID HMAC de la décision
                "mitre_technique": result.get("mitre_technique", ""),  # Technique MITRE
                "mitre_tactic": result.get("mitre_tactic", ""),        # Tactique MITRE
                # ── Détails complets (pour forensique) ───────────────────
                "details": result,                            # Résultat complet du playbook
                "alert_snapshot": {                           # Snapshot minimal de l'alerte
                    "niveau": alert.get("niveau"),
                    "statut": alert.get("statut"),
                    "rule_id": alert.get("rule_id"),
                    "score_risque": alert.get("score_risque"),
                },
                # ── Horodatage ───────────────────────────────────────────
                "executed_at": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception as exc:
        # L'écriture de l'audit ne doit jamais faire échouer le playbook
        # Mais on log l'erreur car c'est un problème de conformité grave
        logger.critical(
            "[AUDIT] ECHEC écriture idx-soar-executions pour playbook=%s : %s",
            result.get("playbook"), exc,
        )


# ─────────────────────────────────────────────
# Instanciation d'un playbook
# ─────────────────────────────────────────────

def _instantiate_playbook(
    playbook_cls: Type[BasePlaybook],
    playbook_name: str,
    es: Any,
) -> BasePlaybook:
    """
    Instancie un playbook avec les dépendances requises (injection).

    Les playbooks nécessitant Elasticsearch reçoivent le client injecté.
    Les autres sont instanciés sans dépendances (ex: block_ip, isolate_machine).
    """
    if playbook_name in _ES_REQUIRED_PLAYBOOKS:
        return playbook_cls(es)   # Injection du client ES
    return playbook_cls()          # Aucune dépendance externe


# ─────────────────────────────────────────────
# Exécution d'un playbook avec retry
# ─────────────────────────────────────────────

async def execute_playbook(
    es: Any,
    *,
    playbook_name: str,
    alert: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Instancie, exécute et audite un playbook de façon sécurisée.

    Sécurités appliquées
    --------------------
    1. Vérification dans la liste blanche PLAYBOOK_REGISTRY
    2. Vérification du circuit-breaker (désactivation si trop d'échecs)
    3. Exécution via safe_execute() (timeout + validation d'alerte)
    4. Retry avec backoff exponentiel (max MAX_RETRIES tentatives)
    5. Écriture systématique dans idx-soar-executions

    Paramètres
    ----------
    es            : Client AsyncElasticsearch.
    playbook_name : Nom du playbook (doit être dans PLAYBOOK_REGISTRY).
    alert         : Alerte SOAR à traiter.

    Retourne
    --------
    Dictionnaire normalisé du résultat (success/skipped/error).
    """
    now = datetime.now(timezone.utc).isoformat()

    # ── [SÉCURITÉ 1] Vérification de la liste blanche ────────────────────
    playbook_cls = PLAYBOOK_REGISTRY.get(playbook_name)
    if playbook_cls is None:
        # Nom inconnu → refus immédiat sans exécution
        result = {
            "status": "error",
            "playbook": playbook_name,
            "reason": f"Playbook {playbook_name!r} inconnu ou non autorisé",
            "executed_at": now,
        }
        await write_execution(es, alert=alert, result=result)
        logger.error("[Executor] Playbook inconnu refusé : %r", playbook_name)
        return result

    # ── [SÉCURITÉ 2] Vérification du circuit-breaker ─────────────────────
    if _circuit_breaker.is_open(playbook_name):
        result = {
            "status": "skipped",
            "playbook": playbook_name,
            "reason": f"Circuit-breaker ouvert pour {playbook_name!r} (trop d'échecs récents)",
            "executed_at": now,
        }
        await write_execution(es, alert=alert, result=result)
        logger.warning("[Executor] Circuit-breaker actif pour %r", playbook_name)
        return result

    # ── [SÉCURITÉ 3 + 4] Exécution avec retry exponentiel ────────────────
    last_result: Optional[Dict[str, Any]] = None

    for attempt in range(1, MAX_RETRIES + 2):   # +2 : essai initial + MAX_RETRIES
        try:
            # Instanciation avec injection de dépendances
            playbook = _instantiate_playbook(playbook_cls, playbook_name, es)

            # Exécution sécurisée (timeout + validation alerte)
            result = await playbook.safe_execute(alert)
            last_result = result

            # ── Mise à jour du circuit-breaker selon le résultat ─────────
            if result.get("status") == "error":
                _circuit_breaker.record_failure(playbook_name)
            else:
                _circuit_breaker.record_success(playbook_name)

            # Pas de retry sur les succès et les skips
            if result.get("status") in ("success", "skipped"):
                break

            # Retry sur les erreurs si on n'est pas au dernier essai
            if attempt <= MAX_RETRIES:
                wait = RETRY_BACKOFF_BASE_S * (2 ** (attempt - 1))
                logger.warning(
                    "[Executor] Erreur playbook %r, retry dans %.1fs (tentative %d/%d)",
                    playbook_name, wait, attempt, MAX_RETRIES + 1,
                )
                await asyncio.sleep(wait)

        except Exception as exc:
            # Exception non prévue dans le playbook
            logger.exception(
                "[Executor] Exception non prévue pour %r (tentative %d) : %s",
                playbook_name, attempt, exc,
            )
            _circuit_breaker.record_failure(playbook_name)
            last_result = {
                "status": "error",
                "playbook": playbook_name,
                "reason": "Exception non prévue dans l'executor SOAR",
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }

    result = last_result or {
        "status": "error",
        "playbook": playbook_name,
        "reason": "Aucun résultat retourné après tous les essais",
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }

    # ── [SÉCURITÉ 5] Écriture dans l'audit trail ─────────────────────────
    await write_execution(es, alert=alert, result=result)

    logger.info(
        "[Executor] playbook=%r status=%s target=%s",
        playbook_name,
        result.get("status"),
        result.get("target"),
    )
    return result


# ─────────────────────────────────────────────
# Exécution d'une chaîne de playbooks
# ─────────────────────────────────────────────

async def execute_playbook_chain(
    es: Any,
    *,
    playbook_names: List[str],
    alert: Dict[str, Any],
    stop_on_error: bool = False,
) -> List[Dict[str, Any]]:
    """
    Exécute une séquence ordonnée de playbooks sur la même alerte.

    Utilisé pour enchaîner collect_forensics → action principale → escalade.

    Paramètres
    ----------
    es             : Client AsyncElasticsearch.
    playbook_names : Liste ordonnée des noms de playbooks à exécuter.
    alert          : Alerte SOAR à traiter.
    stop_on_error  : Si True, arrête la chaîne dès le premier échec.

    Retourne
    --------
    Liste des résultats dans l'ordre d'exécution.
    """
    results: List[Dict[str, Any]] = []

    for name in playbook_names:
        result = await execute_playbook(es, playbook_name=name, alert=alert)
        results.append(result)

        # Arrêt sur erreur si demandé
        if stop_on_error and result.get("status") == "error":
            logger.warning(
                "[Executor] Chaîne arrêtée après échec de %r", name
            )
            break

    logger.info(
        "[Executor] Chaîne %s terminée : %d/%d playbooks exécutés",
        " → ".join(playbook_names),
        len(results),
        len(playbook_names),
    )
    return results
