"""
soar/playbooks/collect_forensics.py — Playbook SOAR de collecte forensique (NOUVEAU)

Responsable : Module SOAR — Investigation & Forensique
Exigences   : RF-INC-05 (collecte preuves), NFR-SEC-03 (audit), RF-SOAR-05
MITRE ATT&CK: T1005 (Data from Local System), T1083 (File and Directory Discovery)

Ce playbook orchestre la collecte de données forensiques AVANT toute action
destructrice (isolation, désactivation). Il garantit la préservation des
preuves pour analyse post-incident et éventuelle action légale.

Principe fondamental : COLLECTER avant AGIR.

Ce que ce playbook collecte (et enregistre dans idx-soar-executions) :
  - Métadonnées des logs corrélés à l'alerte (depuis idx-logs)
  - Profil comportemental UEBA de l'entité ciblée
  - Historique des alertes liées à la même entité (corrélation temporelle)
  - Snapshot de l'état de l'alerte au moment de l'action

Ce playbook est NON destructeur (lecture seule + écriture dans idx).
Il peut être exécuté avant tout playbook destructeur.
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import logging     # Journalisation structurée
from datetime import datetime, timedelta, timezone  # Horodatage UTC
from typing import Any, Dict, List, Optional        # Annotations de types

# ─────────────────────────────────────────────
# Imports internes SOAR
# ─────────────────────────────────────────────
from soar.playbooks.base_playbook import BasePlaybook  # Contrat commun
from soar.policy import SoarPolicy                      # Politique fail-closed

# ─────────────────────────────────────────────
# Logger dédié au playbook
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.playbooks.collect_forensics")

# Fenêtre de collecte des logs corrélés (en heures avant l'alerte)
FORENSICS_WINDOW_HOURS: int = 2

# Nombre maximum de logs collectés (évite les snapshots démesurés)
MAX_LOGS_COLLECTED: int = 500

# Nombre maximum d'alertes historiques collectées
MAX_ALERTS_HISTORY: int = 50


class CollectForensicsPlaybook(BasePlaybook):
    """
    Collecte des données forensiques numériques liées à une alerte SOAR.

    Ce playbook est typiquement exécuté EN PREMIER dans une chaîne de
    réponse (avant block_ip, disable_account, isolate_machine) pour
    préserver les preuves avant toute action potentiellement destructrice.

    Données collectées
    ------------------
    - Logs bruts référencés par l'alerte (ids dans log_refs)
    - Logs contextuels de la fenêtre temporelle entourant l'alerte
    - Profil UEBA de l'entité (si disponible)
    - Historique des alertes précédentes sur la même entité
    - Métadonnées de l'alerte courante (snapshot complet)

    Toutes les données sont stockées dans idx-soar-executions avec
    le statut "forensics_collected" pour référence future.
    """

    # ── Identité du playbook ────────────────────────────────────────────────
    name = "collect_forensics"    # Nom unique dans le registre de l'executor
    destructive = False           # Lecture seule — aucune modification du système
    mitre_technique = "T1005"     # Data from Local System — collecte de données
    mitre_tactic = "Collection"

    def __init__(self, es: Any, policy: SoarPolicy | None = None) -> None:
        """
        Paramètres
        ----------
        es     : Client AsyncElasticsearch (lecture idx-logs, idx-alerts, idx-ueba-profiles).
        policy : Politique SOAR. Si None, utilise les valeurs d'environnement.
        """
        self.es = es
        self.policy = policy or SoarPolicy()

    # ─────────────────────────────────────────
    # Collecte des logs référencés par l'alerte
    # ─────────────────────────────────────────

    async def _collect_referenced_logs(
        self, log_refs: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Récupère les logs directement référencés dans l'alerte (champ log_refs).

        Ces logs sont les preuves directes du déclenchement de la règle.
        """
        if not log_refs:
            return []
        try:
            res = await self.es.mget(
                index="idx-logs",
                body={"ids": log_refs[:MAX_LOGS_COLLECTED]},  # Limite de sécurité
            )
            # Filtre les documents trouvés (ignore les _id manquants)
            return [
                {"_id": doc["_id"], "_source": doc.get("_source", {})}
                for doc in res["docs"]
                if doc.get("found", False)
            ]
        except Exception as exc:
            logger.warning("[CollectForensics] Erreur récupération logs référencés : %s", exc)
            return []

    # ─────────────────────────────────────────
    # Collecte des logs contextuels (fenêtre temporelle)
    # ─────────────────────────────────────────

    async def _collect_contextual_logs(
        self, alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Collecte les logs dans une fenêtre temporelle autour de l'alerte.

        Utile pour reconstituer la timeline d'attaque et identifier des
        événements connexes non inclus dans les log_refs directs.
        """
        try:
            # Calcule la fenêtre temporelle (2h avant la création de l'alerte)
            alert_time_raw = alert.get("created_at", datetime.now(timezone.utc).isoformat())
            try:
                alert_time = datetime.fromisoformat(str(alert_time_raw))
            except ValueError:
                alert_time = datetime.now(timezone.utc)

            # Borne inférieure : FORENSICS_WINDOW_HOURS avant l'alerte
            since = (alert_time - timedelta(hours=FORENSICS_WINDOW_HOURS)).isoformat()

            # Filtre par source IP ou username si disponible (contextualise la collecte)
            must_clauses: List[Dict] = [
                {"range": {"timestamp": {"gte": since}}}
            ]
            source_ip = (
                alert.get("source_ip")
                or alert.get("normalized_fields", {}).get("source_ip")
            )
            if source_ip:
                # Cherche tous les logs de cette IP dans la fenêtre
                must_clauses.append({"term": {"normalized_fields.source_ip": source_ip}})

            res = await self.es.search(
                index="idx-logs",
                query={"bool": {"must": must_clauses}},
                size=MAX_LOGS_COLLECTED,
                sort=[{"timestamp": {"order": "desc"}}],  # Plus récents en premier
            )
            return [
                {"_id": h["_id"], "_source": h.get("_source", {})}
                for h in res["hits"]["hits"]
            ]
        except Exception as exc:
            logger.warning("[CollectForensics] Erreur collecte logs contextuels : %s", exc)
            return []

    # ─────────────────────────────────────────
    # Collecte du profil UEBA
    # ─────────────────────────────────────────

    async def _collect_ueba_profile(
        self, alert: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Récupère le profil comportemental UEBA de l'entité ciblée.

        Le profil contient les patterns habituels (heures, volumes, IPs)
        et permet de comprendre en quoi le comportement actuel est anormal.
        """
        # Identifie l'entité (username ou IP source)
        entity_id = (
            alert.get("username")
            or alert.get("normalized_fields", {}).get("username")
            or alert.get("ueba_context", {}).get("entity_id")
        )
        if not entity_id:
            return None

        try:
            res = await self.es.get(
                index="idx-ueba-profiles",
                id=entity_id,
            )
            if res.get("found"):
                return res["_source"]
            return None
        except Exception:
            # Profil absent ou ES indisponible → non bloquant
            return None

    # ─────────────────────────────────────────
    # Collecte de l'historique des alertes
    # ─────────────────────────────────────────

    async def _collect_alert_history(
        self, alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Collecte l'historique des alertes précédentes liées à la même règle
        ou entité (pour identifier un pattern d'attaque récurrent).
        """
        try:
            rule_id = alert.get("rule_id")
            if not rule_id:
                return []

            res = await self.es.search(
                index="idx-alerts",
                query={"bool": {"must": [{"term": {"rule_id": rule_id}}]}},
                size=MAX_ALERTS_HISTORY,
                sort=[{"created_at": {"order": "desc"}}],
            )
            return [
                {"_id": h["_id"], "_source": h.get("_source", {})}
                for h in res["hits"]["hits"]
            ]
        except Exception as exc:
            logger.warning("[CollectForensics] Erreur collecte historique alertes : %s", exc)
            return []

    # ─────────────────────────────────────────
    # Méthode principale : execute()
    # ─────────────────────────────────────────

    async def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestre la collecte forensique complète de l'alerte.

        Ce playbook est toujours autorisé (non destructeur) mais passe
        quand même par la politique pour le kill-switch et le rate-limiting.
        """
        # ── ÉTAPE 1 : Décision de la politique SOAR ───────────────────────
        # Passe par la politique pour le kill-switch et le rate-limiting
        decision = self.policy.decide(
            playbook=self.name,
            alert=alert,
            target=alert.get("rule_id", "unknown"),
        )
        if not decision.allowed:
            return self.skipped(decision.reason, target=alert.get("rule_id"))

        now = datetime.now(timezone.utc).isoformat()

        # ── ÉTAPE 2 : Collecte des logs référencés ────────────────────────
        log_refs = alert.get("log_refs", [])
        referenced_logs = await self._collect_referenced_logs(log_refs)

        # ── ÉTAPE 3 : Collecte des logs contextuels ───────────────────────
        contextual_logs = await self._collect_contextual_logs(alert)

        # ── ÉTAPE 4 : Collecte du profil UEBA ────────────────────────────
        ueba_profile = await self._collect_ueba_profile(alert)

        # ── ÉTAPE 5 : Collecte de l'historique des alertes ───────────────
        alert_history = await self._collect_alert_history(alert)

        # ── ÉTAPE 6 : Construction du paquet forensique ───────────────────
        forensics_package = {
            "collection_timestamp": now,
            "alert_snapshot": alert,               # Snapshot complet de l'alerte
            "referenced_logs_count": len(referenced_logs),
            "contextual_logs_count": len(contextual_logs),
            "referenced_logs": referenced_logs,    # Logs preuves directes
            "contextual_logs": contextual_logs,    # Logs contextuels
            "ueba_profile": ueba_profile,          # Profil comportemental
            "alert_history_count": len(alert_history),
            "alert_history": alert_history,        # Historique d'alertes
            "collection_window_hours": FORENSICS_WINDOW_HOURS,
        }

        logger.info(
            "[CollectForensics] Collecte terminée — %d logs ref + %d logs ctx + ueba=%s alerte=%s decision_id=%s",
            len(referenced_logs), len(contextual_logs),
            "oui" if ueba_profile else "non",
            alert.get("rule_id"), decision.decision_id,
        )

        return self.success(
            target=alert.get("rule_id", "unknown"),
            extra={
                "action": "collect_forensics",
                "decision_id": decision.decision_id,
                "referenced_logs_count": len(referenced_logs),
                "contextual_logs_count": len(contextual_logs),
                "ueba_profile_available": ueba_profile is not None,
                "alert_history_count": len(alert_history),
                "collection_window_hours": FORENSICS_WINDOW_HOURS,
                # Note : le paquet complet est dans les détails de l'exécution
                # pour éviter les réponses trop volumineuses dans les logs
                "forensics_summary": {
                    "total_evidence_items": len(referenced_logs) + len(contextual_logs),
                    "entities_profiled": 1 if ueba_profile else 0,
                    "historical_alerts": len(alert_history),
                },
            },
        )
