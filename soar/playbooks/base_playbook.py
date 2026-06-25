"""
soar/playbooks/base_playbook.py — Contrat strict commun à tous les playbooks SOAR

Responsable : Module SOAR
Exigences   : RF-SOAR-01 (playbooks standardisés), NFR-SEC-03 (audit trail),
              NFR-SEC-05 (non-répudiation), RF-INC-04 (journalisation des actions)

Ce module définit la classe abstraite dont TOUS les playbooks doivent hériter.
Il garantit :
  * Un format d'entrée/sortie normalisé et versionnisé
  * Un audit trail complet pour chaque action (succès, échec, skip)
  * La traçabilité MITRE ATT&CK (technique liée à l'alerte)
  * Un timeout maximal sur les actions (prévient les blocages)
  * La validation de la structure minimale d'une alerte SOAR

Principe : aucun playbook ne peut s'exécuter sans passer par ce contrat.
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import asyncio         # Timeout asynchrone pour les actions longues
import logging         # Journalisation structurée
from abc import ABC, abstractmethod   # Classe abstraite imposant le contrat
from datetime import datetime, timezone  # Horodatage UTC strict
from typing import Any, Dict, Optional   # Annotations de types

# ─────────────────────────────────────────────
# Configuration du logger de base
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.playbooks")

# ─────────────────────────────────────────────
# Constantes du contrat de playbook
# ─────────────────────────────────────────────

# Durée maximale d'exécution d'un playbook (en secondes)
# Au-delà, asyncio.TimeoutError est levé et l'exécution est annulée
PLAYBOOK_TIMEOUT_S: int = 30

# Champs obligatoires minimaux dans toute alerte traitée par un playbook
REQUIRED_ALERT_FIELDS: frozenset = frozenset({"niveau", "statut"})

# Version du protocole de playbook (pour la compatibilité future)
PLAYBOOK_PROTOCOL_VERSION: str = "1.0"


class BasePlaybook(ABC):
    """
    Interface minimale, auditable et sécurisée pour une action de réponse SOAR.

    Attributs de classe (à surcharger dans chaque playbook)
    -------------------------------------------------------
    name        : Identifiant machine du playbook (snake_case, unique dans le registre).
    destructive : True si le playbook peut modifier l'état du système (réseau, compte, etc.).
    mitre_technique : Identifiant de la technique MITRE ATT&CK associée (ex: "T1110").

    Cycle de vie d'un playbook
    --------------------------
    1. L'executor instancie le playbook
    2. L'executor appelle `validate_alert(alert)` pour vérifier la structure
    3. L'executor appelle `execute(alert)` avec un timeout
    4. Le résultat est écrit dans `idx-soar-executions` par l'executor

    Jamais :
    --------
    * Un playbook n'écrit lui-même dans idx-soar-executions (responsabilité de l'executor)
    * Un playbook ne contient de credentials en dur
    * Un playbook n'effectue d'actions réseaux sans passer par tls_client
    """

    # ── Attributs de classe — à redéfinir dans chaque sous-classe ──────────
    name: str = "base"               # Nom unique du playbook
    destructive: bool = False        # True = action irréversible possible
    mitre_technique: str = ""        # Ex: "T1110" (Brute Force)
    mitre_tactic: str = ""           # Ex: "Credential Access"

    # ─────────────────────────────────────────
    # Utilitaires communs
    # ─────────────────────────────────────────

    def now(self) -> str:
        """
        Retourne le timestamp UTC courant au format ISO-8601.
        Utilisé pour tous les champs d'horodatage des traces SOAR.
        """
        return datetime.now(timezone.utc).isoformat()

    def validate_alert(self, alert: Dict[str, Any]) -> Optional[str]:
        """
        Valide la structure minimale d'une alerte avant exécution.

        Retourne None si l'alerte est valide.
        Retourne une raison de refus si des champs obligatoires sont manquants.

        Un playbook ne devrait jamais s'exécuter sur une alerte mal formée,
        car cela pourrait conduire à des actions sur de mauvaises cibles.
        """
        # ── Vérifie la présence des champs obligatoires ───────────────────
        missing = REQUIRED_ALERT_FIELDS - set(alert.keys())
        if missing:
            return f"Champs obligatoires manquants dans l'alerte : {sorted(missing)}"

        # ── Vérifie que le niveau est reconnu ─────────────────────────────
        niveau = str(alert.get("niveau", "")).upper()
        if niveau not in {"INFO", "WARNING", "HIGH", "CRITICAL"}:
            return f"Niveau d'alerte non reconnu : {niveau!r}"

        return None  # Alerte valide

    # ─────────────────────────────────────────
    # Constructeurs de réponses normalisées
    # ─────────────────────────────────────────

    def success(
        self,
        *,
        target: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Construit une réponse de succès normalisée pour l'audit trail.

        Paramètres
        ----------
        target : Identifiant de la cible traitée (IP, username, hostname).
        extra  : Champs additionnels spécifiques au playbook (action, dry_run, etc.).

        Retourne
        --------
        Un dictionnaire avec tous les champs requis par idx-soar-executions.
        """
        return {
            "status": "success",               # Statut normalisé de l'exécution
            "playbook": self.name,             # Nom du playbook exécuté
            "target": target,                  # Cible de l'action
            "destructive": self.destructive,   # Indique si l'action est irréversible
            "mitre_technique": self.mitre_technique,  # Mapping MITRE ATT&CK
            "mitre_tactic": self.mitre_tactic,        # Tactique MITRE
            "protocol_version": PLAYBOOK_PROTOCOL_VERSION,  # Version du protocole
            "executed_at": self.now(),         # Timestamp UTC de l'exécution
            **(extra or {}),                   # Champs additionnels du playbook
        }

    def skipped(
        self,
        reason: str,
        *,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Construit une réponse de skip (action non destructive, condition non remplie).

        Un skip n'est pas une erreur : c'est une décision délibérée de ne pas agir
        (ex: IP privée, compte protégé, niveau insuffisant).
        """
        return {
            "status": "skipped",               # Exécution ignorée (non destructif)
            "playbook": self.name,
            "target": target,
            "reason": reason,                  # Explication du skip pour l'audit
            "destructive": self.destructive,
            "protocol_version": PLAYBOOK_PROTOCOL_VERSION,
            "executed_at": self.now(),
        }

    def failed(
        self,
        reason: str,
        *,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Construit une réponse d'échec sans exposer de détails techniques sensibles.

        Note : La raison est volontairement générique pour éviter les fuites
        d'information dans les logs (ex: pas de stack trace complète).
        """
        return {
            "status": "error",                 # Exécution échouée
            "playbook": self.name,
            "target": target,
            "reason": reason,                  # Raison générique (pas de traceback)
            "destructive": self.destructive,
            "protocol_version": PLAYBOOK_PROTOCOL_VERSION,
            "executed_at": self.now(),
        }

    # ─────────────────────────────────────────
    # Méthode abstraite : point d'entrée
    # ─────────────────────────────────────────

    @abstractmethod
    async def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exécute le playbook sur une alerte déjà validée par la politique SOAR.

        Contrat
        -------
        * Doit retourner un dictionnaire produit par success(), skipped() ou failed()
        * Ne doit jamais lever d'exception non attrapée (utiliser failed())
        * Ne doit jamais bloquer plus de PLAYBOOK_TIMEOUT_S secondes
        * Toute action destructive doit être précédée d'une vérification policy.decide()

        Paramètres
        ----------
        alert : Alerte SOAR validée (a passé validate_alert() avec succès).

        Retourne
        --------
        Un dictionnaire normalisé (voir success(), skipped(), failed()).
        """
        raise NotImplementedError

    async def safe_execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Wrapper sécurisé autour de execute() avec timeout et validation.

        Cette méthode est appelée par l'executor à la place de execute() directement.
        Elle garantit :
          * La validation de la structure de l'alerte
          * Un timeout maximum (PLAYBOOK_TIMEOUT_S)
          * La capture des exceptions non prévues en failed()
        """
        # ── Validation de l'alerte avant tout ────────────────────────────
        validation_error = self.validate_alert(alert)
        if validation_error:
            logger.warning(
                "[%s] Alerte invalide : %s", self.name, validation_error
            )
            return self.skipped(f"Alerte invalide : {validation_error}")

        # ── Exécution avec timeout strict ────────────────────────────────
        try:
            return await asyncio.wait_for(
                self.execute(alert),
                timeout=PLAYBOOK_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            logger.error(
                "[%s] Timeout après %ds — exécution annulée",
                self.name, PLAYBOOK_TIMEOUT_S,
            )
            return self.failed(
                f"Timeout dépassé ({PLAYBOOK_TIMEOUT_S}s) — action annulée"
            )
        except Exception as exc:
            # Capture toute exception inattendue pour éviter un crash de l'executor
            logger.exception("[%s] Exception non prévue : %s", self.name, exc)
            return self.failed("Erreur technique interne — voir les logs SOAR")
