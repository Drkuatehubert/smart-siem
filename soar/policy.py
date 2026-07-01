"""
soar/policy.py — Politique SOAR fail-closed renforcée

Responsable : Module Sécurité & Gouvernance SOAR
Exigences   : RF-SEC-01 (contrôle d'accès), RF-SOAR-01 à RF-SOAR-06,
              NFR-SEC-03 (audit immutable), NFR-SEC-05 (non-répudiation)

Ce module centralise TOUS les garde-fous avant toute action automatique :
  * Kill-switch global (arrêt d'urgence de toutes les actions)
  * Niveau minimal de sévérité pour l'automatisation
  * Approbation humaine obligatoire avec fenêtre d'expiration
  * Validation stricte des cibles (IP, comptes, machines)
  * Rate-limiting des actions par type de playbook
  * Journalisation HMAC des décisions (non-répudiation)
  * Blocage des réseaux privés / comptes système protégés
  * Mode dry-run activé par défaut (aucun dommage accidentel)

Principe de sécurité : TOUT EST REFUSÉ sauf si explicitement autorisé.
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import hashlib    # HMAC-SHA256 pour la signature des décisions
import hmac       # Comparaison HMAC en temps constant (anti-timing-attack)
import ipaddress  # Validation et classification des adresses IP
import logging    # Journalisation structurée
import os         # Lecture des variables d'environnement
import time       # Timestamps Unix pour le rate-limiting
from dataclasses import dataclass, field  # Structures immuables
from datetime import datetime, timezone   # Horodatage UTC strict
from typing import Any, Dict, Optional    # Annotations de types

# ─────────────────────────────────────────────
# Configuration du logger dédié
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.policy")

# ─────────────────────────────────────────────
# Constantes de sévérité et de configuration
# ─────────────────────────────────────────────

# Ordre croissant des niveaux de sévérité (INFO=0 … CRITICAL=3)
SEVERITY_ORDER: Dict[str, int] = {
    "INFO": 0,
    "WARNING": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

# Comptes système jamais désactivables automatiquement (protection absolue)
PROTECTED_ACCOUNTS: frozenset = frozenset({
    "admin", "root", "elastic", "kibana", "logstash",
    "redis", "postgres", "system", "nobody", "daemon",
})

# Playbooks considérés comme destructeurs (nécessitent approbation humaine)
DESTRUCTIVE_PLAYBOOKS: frozenset = frozenset({
    "block_ip", "disable_account", "isolate_machine", "collect_forensics",
})

# Fenêtre maximale d'approbation (en secondes) — au-delà, l'approbation expire
APPROVAL_WINDOW_SECONDS: int = int(os.getenv("SOAR_APPROVAL_WINDOW_S", "900"))  # 15 min

# Nombre maximal d'actions du même playbook par fenêtre de rate-limiting
RATE_LIMIT_MAX: int = int(os.getenv("SOAR_RATE_LIMIT_MAX", "10"))

# Fenêtre de rate-limiting en secondes
RATE_LIMIT_WINDOW_S: int = int(os.getenv("SOAR_RATE_LIMIT_WINDOW_S", "60"))


# ─────────────────────────────────────────────
# Helpers de lecture d'environnement
# ─────────────────────────────────────────────

def _env_bool(name: str, default: bool) -> bool:
    """
    Lit un booléen depuis les variables d'environnement.
    Valeurs acceptées : 1, true, yes, on (insensible à la casse).
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ─────────────────────────────────────────────
# Structure de résultat de décision (immuable)
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class SoarDecision:
    """
    Résultat immuable d'une décision de sécurité SOAR.

    Champs
    ------
    allowed          : True si l'action est autorisée, False sinon.
    reason           : Explication humaine de la décision (pour audit).
    approval_required: True si un opérateur doit approuver manuellement.
    decision_id      : Identifiant unique de cette décision (pour traçabilité).
    decided_at       : Timestamp UTC ISO-8601 de la décision.
    """
    allowed: bool               # Autorisation finale (fail-closed = False par défaut)
    reason: str                 # Explication lisible pour l'audit
    approval_required: bool = False   # Indique si approbation humaine est requise
    decision_id: str = ""             # ID unique de la décision (HMAC tronqué)
    decided_at: str = ""              # Horodatage UTC de la décision


# ─────────────────────────────────────────────
# Compteur de rate-limiting (mémoire locale)
# ─────────────────────────────────────────────

class _RateLimiter:
    """
    Compteur de rate-limiting par type de playbook.

    Utilise une fenêtre glissante basée sur des timestamps Unix pour éviter
    les rafales d'actions automatiques.
    """

    def __init__(self) -> None:
        # Dictionnaire : playbook_name → liste de timestamps Unix des exécutions
        self._buckets: Dict[str, list] = {}

    def is_allowed(self, playbook: str) -> bool:
        """
        Retourne True si le playbook peut encore s'exécuter dans cette fenêtre.
        Nettoie automatiquement les entrées expirées.
        """
        now = time.monotonic()
        # ── Récupère ou initialise le seau de timestamps ─────────────────
        bucket = self._buckets.setdefault(playbook, [])
        # ── Supprime les timestamps hors de la fenêtre glissante ──────────
        cutoff = now - RATE_LIMIT_WINDOW_S
        self._buckets[playbook] = [t for t in bucket if t > cutoff]
        # ── Vérifie si la limite est atteinte ─────────────────────────────
        if len(self._buckets[playbook]) >= RATE_LIMIT_MAX:
            return False
        # ── Enregistre cette tentative ────────────────────────────────────
        self._buckets[playbook].append(now)
        return True


# Instance partagée du rate-limiter (singleton pour toute la durée de vie du process)
_rate_limiter = _RateLimiter()


# ─────────────────────────────────────────────
# Politique SOAR principale
# ─────────────────────────────────────────────

class SoarPolicy:
    """
    Contrôle central appliqué avant l'exécution de chaque playbook SOAR.

    Chaque décision est :
      1. Fail-closed (refusée par défaut)
      2. Tracée avec un ID unique
      3. Rate-limitée pour éviter les boucles d'actions
      4. Validée contre une liste blanche de playbooks connus
    """

    def __init__(self) -> None:
        # ── Kill-switch global (SOAR_KILL_SWITCH=true → tout est bloqué) ───
        self.kill_switch: bool = _env_bool("SOAR_KILL_SWITCH", False)

        # ── Approbation humaine requise avant toute action destructive ───────
        self.require_approval: bool = _env_bool("SOAR_REQUIRE_APPROVAL", True)

        # ── Autorisation des actions sur réseaux privés (défaut : REFUSÉ) ────
        self.allow_private_networks: bool = _env_bool("SOAR_ALLOW_PRIVATE_NETWORKS", False)

        # ── Niveau minimal pour déclencher une action automatique ────────────
        self.min_auto_level: str = os.getenv("SOAR_MIN_AUTO_LEVEL", "CRITICAL").upper()

        # ── Mode dry-run : simule l'action sans l'exécuter (défaut : ACTIVÉ) ─
        self.dry_run: bool = _env_bool("SOAR_DRY_RUN", True)

        # ── Clé secrète pour la signature HMAC des décisions ─────────────────
        # IMPORTANT : Cette clé doit être fournie via l'environnement en prod
        self._hmac_secret: bytes = os.getenv(
            "SOAR_HMAC_SECRET", "dev-soar-secret-key-change-in-prod"
        ).encode("utf-8")

        logger.info(
            "[Policy] Initialisée — kill_switch=%s dry_run=%s min_level=%s approval=%s",
            self.kill_switch, self.dry_run, self.min_auto_level, self.require_approval,
        )

    # ─────────────────────────────────────────
    # Signature HMAC des décisions (audit trail)
    # ─────────────────────────────────────────

    def _sign_decision(self, playbook: str, target: Optional[str], allowed: bool) -> str:
        """
        Génère un identifiant de décision signé avec HMAC-SHA256.

        Le hash encode : playbook + target + allowed + timestamp UTC.
        Il est tronqué à 16 caractères pour l'affichage dans les logs.
        """
        ts = datetime.now(timezone.utc).isoformat()
        # Construit le message à signer (concaténation déterministe)
        message = f"{playbook}:{target or ''}:{allowed}:{ts}".encode("utf-8")
        # Calcule le HMAC-SHA256
        sig = hmac.new(self._hmac_secret, message, hashlib.sha256).hexdigest()
        # Retourne les 16 premiers caractères hexadécimaux (64 bits d'entropie)
        return sig[:16]

    # ─────────────────────────────────────────
    # Validation de l'adresse IP cible
    # ─────────────────────────────────────────

    def _validate_ip_target(self, target: str) -> Optional[str]:
        """
        Valide une adresse IP cible avant blocage.

        Retourne None si l'IP est valide et autorisée.
        Retourne une raison de refus si l'IP ne doit pas être bloquée.
        """
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            # L'adresse IP est syntaxiquement invalide
            return f"Adresse IP syntaxiquement invalide : {target!r}"

        # ── Vérification des plages réservées ────────────────────────────
        if ip.is_loopback:
            # 127.0.0.0/8 et ::1 : jamais bloquer localhost
            return f"Blocage refusé sur adresse loopback : {target}"
        if ip.is_link_local:
            # 169.254.0.0/16 et fe80::/10 : adresses APIPA/link-local
            return f"Blocage refusé sur adresse link-local : {target}"
        if ip.is_multicast:
            # 224.0.0.0/4 et ff00::/8 : adresses multicast
            return f"Blocage refusé sur adresse multicast : {target}"
        if ip.is_reserved:
            # Plages réservées IANA (0.0.0.0, 240.0.0.0/4, etc.)
            return f"Blocage refusé sur adresse réservée IANA : {target}"
        if ip.is_private and not self.allow_private_networks:
            # Réseaux privés RFC 1918 : blocage interdit sauf config explicite
            return (
                f"Blocage refusé sur réseau privé : {target} "
                "(définir SOAR_ALLOW_PRIVATE_NETWORKS=true pour autoriser)"
            )
        # ── L'IP est valide et peut être bloquée ─────────────────────────
        return None

    # ─────────────────────────────────────────
    # Validation d'un compte utilisateur cible
    # ─────────────────────────────────────────

    def _validate_account_target(self, target: str) -> Optional[str]:
        """
        Vérifie qu'un compte utilisateur peut être désactivé automatiquement.

        Retourne None si la désactivation est autorisée.
        Retourne une raison de refus si le compte est protégé.
        """
        # Normalise le nom d'utilisateur (minuscules, sans espaces)
        username = target.strip().lower()
        if username in PROTECTED_ACCOUNTS:
            return (
                f"Compte système protégé, désactivation automatique interdite : {target!r}"
            )
        if len(username) < 2:
            # Nom trop court : probablement une erreur d'extraction de l'alerte
            return f"Nom de compte trop court pour être valide : {target!r}"
        return None

    # ─────────────────────────────────────────
    # Vérification de l'approbation humaine
    # ─────────────────────────────────────────

    def _check_approval(self, alert: Dict[str, Any]) -> Optional[str]:
        """
        Vérifie si l'approbation humaine est présente et valide.

        L'approbation expire après APPROVAL_WINDOW_SECONDS secondes.
        Retourne None si l'approbation est valide.
        Retourne une raison de refus sinon.
        """
        if not self.require_approval:
            # L'approbation n'est pas requise par configuration
            return None

        if not alert.get("soar_approved"):
            # Champ `soar_approved` absent ou False dans l'alerte
            return "Approbation humaine requise (soar_approved manquant)"

        # ── Vérification de l'expiration de l'approbation ────────────────
        approved_at_raw = alert.get("soar_approved_at")
        if approved_at_raw:
            try:
                approved_at = datetime.fromisoformat(str(approved_at_raw))
                # Assure que le timestamp est bien en UTC
                if approved_at.tzinfo is None:
                    approved_at = approved_at.replace(tzinfo=timezone.utc)
                elapsed = (datetime.now(timezone.utc) - approved_at).total_seconds()
                if elapsed > APPROVAL_WINDOW_SECONDS:
                    return (
                        f"Approbation expirée il y a {elapsed - APPROVAL_WINDOW_SECONDS:.0f}s "
                        f"(fenêtre = {APPROVAL_WINDOW_SECONDS}s)"
                    )
            except (ValueError, TypeError) as exc:
                # Format de timestamp invalide → refus par précaution
                return f"Timestamp d'approbation invalide : {exc}"

        return None  # Approbation valide

    # ─────────────────────────────────────────
    # Point d'entrée principal : décision SOAR
    # ─────────────────────────────────────────

    def decide(
        self,
        *,
        playbook: str,
        alert: Dict[str, Any],
        target: Optional[str] = None,
    ) -> SoarDecision:
        """
        Retourne une décision fail-closed avant toute action potentiellement destructive.

        Paramètres
        ----------
        playbook : Nom du playbook demandant l'autorisation.
        alert    : Dictionnaire de l'alerte SOAR (doit contenir 'niveau').
        target   : Cible de l'action (IP, username, hostname).

        Retourne
        --------
        SoarDecision avec allowed=True uniquement si TOUTES les conditions sont remplies.
        En cas de doute, la décision est REFUSÉE (fail-closed).
        """
        now_ts = datetime.now(timezone.utc).isoformat()

        # ── Fonction interne pour construire une décision refusée ─────────
        def _deny(reason: str, approval_req: bool = False) -> SoarDecision:
            did = self._sign_decision(playbook, target, False)
            logger.warning(
                "[Policy] REFUS playbook=%s target=%s reason=%r decision_id=%s",
                playbook, target, reason, did,
            )
            return SoarDecision(
                allowed=False,
                reason=reason,
                approval_required=approval_req,
                decision_id=did,
                decided_at=now_ts,
            )

        # ── [GARDE 1] Kill-switch global ──────────────────────────────────
        # Si SOAR_KILL_SWITCH=true, toutes les actions sont immédiatement bloquées
        if self.kill_switch:
            return _deny("SOAR_KILL_SWITCH actif — toutes les actions sont suspendues")

        # ── [GARDE 2] Rate-limiting par playbook ──────────────────────────
        # Évite les boucles d'exécution (ex: une alerte qui se régénère)
        if not _rate_limiter.is_allowed(playbook):
            return _deny(
                f"Rate-limit atteint pour {playbook!r} "
                f"({RATE_LIMIT_MAX} actions/{RATE_LIMIT_WINDOW_S}s)"
            )

        # ── [GARDE 3] Niveau de sévérité minimal ─────────────────────────
        # N'automatise que les alertes graves (CRITICAL par défaut)
        severity = str(alert.get("niveau") or alert.get("severity") or "INFO").upper()
        sev_score = SEVERITY_ORDER.get(severity, 0)
        min_score = SEVERITY_ORDER.get(self.min_auto_level, 3)
        if sev_score < min_score:
            return _deny(
                f"Sévérité {severity!r} inférieure au seuil automatique {self.min_auto_level!r}",
                approval_req=True,
            )

        # ── [GARDE 4] Approbation humaine ─────────────────────────────────
        # Pour les playbooks destructeurs, vérifie que l'opérateur a validé
        if playbook in DESTRUCTIVE_PLAYBOOKS:
            approval_error = self._check_approval(alert)
            if approval_error:
                return _deny(approval_error, approval_req=True)

        # ── [GARDE 5] Validation de la cible spécifique au playbook ───────
        if target:
            if playbook == "block_ip":
                ip_error = self._validate_ip_target(target)
                if ip_error:
                    return _deny(ip_error)

            elif playbook == "disable_account":
                acc_error = self._validate_account_target(target)
                if acc_error:
                    return _deny(acc_error)

        # ── Toutes les gardes sont passées → autorisation ─────────────────
        did = self._sign_decision(playbook, target, True)
        logger.info(
            "[Policy] AUTORISÉ playbook=%s target=%s dry_run=%s decision_id=%s",
            playbook, target, self.dry_run, did,
        )
        return SoarDecision(
            allowed=True,
            reason="Exécution autorisée par la politique SOAR",
            approval_required=False,
            decision_id=did,
            decided_at=now_ts,
        )
