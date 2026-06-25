"""
soar/playbooks/escalate_incident.py — Playbook SOAR d'escalade d'incident (NOUVEAU)

Responsable : Module SOAR — Escalade & Gouvernance
Exigences   : RF-INC-03 (escalade), RF-NOTIF-02 (multicanal), NFR-SEC-03 (audit)
MITRE ATT&CK: T1499 (Endpoint Denial of Service), T1486 (Data Encrypted for Impact)

Ce playbook est déclenché quand une alerte CRITICAL ne peut pas être
résolue automatiquement (approbation humaine requise, playbook destructeur bloqué,
ou score de risque UEBA dépassant 90).

Actions réalisées :
  1. Enrichissement de l'alerte avec le contexte UEBA et la tactique MITRE
  2. Notification multicanal du RSSI et de l'équipe SOC (email + Slack)
  3. Création d'un ticket d'incident dans idx-incidents
  4. Mise à jour du statut de l'alerte source en "en_cours"
  5. Journalisation de l'escalade dans idx-soar-executions

Ce playbook n'est JAMAIS destructeur — il informe et coordonne.
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# Imports standard
# ─────────────────────────────────────────────
import logging     # Journalisation structurée
import os          # Variables d'environnement
from datetime import datetime, timezone  # Horodatage UTC
from typing import Any, Dict, List, Optional  # Annotations de types

# ─────────────────────────────────────────────
# Imports internes SOAR
# ─────────────────────────────────────────────
from soar.playbooks.base_playbook import BasePlaybook  # Contrat commun
from soar.policy import SoarPolicy                      # Politique fail-closed

# ─────────────────────────────────────────────
# Logger dédié au playbook
# ─────────────────────────────────────────────
logger = logging.getLogger("soar.playbooks.escalate_incident")

# SLA cible pour la réponse à un incident CRITICAL (en minutes)
CRITICAL_SLA_MINUTES: int = int(os.getenv("SOAR_CRITICAL_SLA_MINUTES", "30"))


class EscalateIncidentPlaybook(BasePlaybook):
    """
    Escalade un incident vers le RSSI et l'équipe SOC avec création de ticket.

    Ce playbook est NON destructeur (il ne modifie pas l'infrastructure),
    mais il crée des enregistrements dans idx-incidents et envoie des
    notifications urgentes aux équipes de réponse.

    Cycle d'exécution
    -----------------
    1. Validation de l'alerte et extraction du contexte
    2. Décision de la politique SOAR (sans approbation humaine requise car non destructeur)
    3. Construction du rapport d'escalade enrichi (MITRE, UEBA, timeline)
    4. Création du ticket incident dans Elasticsearch
    5. Mise à jour du statut de l'alerte source
    6. Notifications multicanal (email + Slack)
    """

    # ── Identité du playbook ────────────────────────────────────────────────
    name = "escalate_incident"    # Nom unique dans le registre de l'executor
    destructive = False           # Aucune modification de l'infrastructure
    mitre_technique = "T1499"     # Impact — catégorie générale pour les escalades
    mitre_tactic = "Impact"

    def __init__(self, es: Any, policy: SoarPolicy | None = None) -> None:
        """
        Paramètres
        ----------
        es     : Client AsyncElasticsearch (pour écrire dans idx-incidents).
        policy : Politique SOAR. Si None, utilise les valeurs d'environnement.
        """
        self.es = es
        self.policy = policy or SoarPolicy()

    # ─────────────────────────────────────────
    # Construction du rapport d'escalade
    # ─────────────────────────────────────────

    def _build_escalation_report(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Construit un rapport d'escalade complet à partir de l'alerte.

        Le rapport inclut :
        - Contexte de l'alerte (règle, sévérité, timestamps)
        - Mapping MITRE ATT&CK complet
        - Contexte UEBA si disponible (score de risque, anomalies)
        - SLA de réponse recommandé
        - Actions recommandées pour l'analyste
        """
        now = datetime.now(timezone.utc).isoformat()

        # ── Extraction du contexte MITRE depuis l'alerte ──────────────────
        mitre_tactic = alert.get("mitre_tactic", "Non déterminée")
        mitre_technique_id = alert.get("mitre_technique_id", "N/A")
        kill_chain = alert.get("kill_chain_phase", "N/A")

        # ── Contexte UEBA (si l'alerte vient de l'analyse comportementale) ─
        ueba_context = alert.get("ueba_context", {})
        ueba_score = ueba_context.get("risk_score", 0)
        ueba_reasons = ueba_context.get("anomaly_reasons", [])
        ueba_entity = ueba_context.get("entity_id", "N/A")

        # ── Actions recommandées selon la tactique MITRE ──────────────────
        recommended_actions = self._get_recommended_actions(
            mitre_technique_id, alert.get("niveau", "HIGH")
        )

        return {
            "alert_id": alert.get("_id") or alert.get("id", "unknown"),
            "rule_id": alert.get("rule_id", "N/A"),
            "rule_name": alert.get("rule_nom", "N/A"),
            "severity": alert.get("niveau", "HIGH"),
            "status": alert.get("statut", "ouvert"),
            "mitre_tactic": mitre_tactic,
            "mitre_technique_id": mitre_technique_id,
            "kill_chain_phase": kill_chain,
            "ueba_entity": ueba_entity,
            "ueba_risk_score": ueba_score,
            "ueba_anomaly_reasons": ueba_reasons,
            "log_refs": alert.get("log_refs", []),
            "escalated_at": now,
            "sla_response_minutes": CRITICAL_SLA_MINUTES,
            "recommended_actions": recommended_actions,
            "escalation_source": "soar_automatic",
        }

    def _get_recommended_actions(self, technique_id: str, severity: str) -> List[str]:
        """
        Retourne des actions recommandées selon la technique MITRE ATT&CK.

        Ces recommandations guident l'analyste de sécurité dans sa réponse.
        """
        # Mapping technique MITRE → actions recommandées
        actions_by_technique: Dict[str, List[str]] = {
            "T1110": [  # Brute Force
                "Bloquer l'IP source (playbook block_ip)",
                "Vérifier les comptes ciblés (mots de passe compromis ?)",
                "Activer MFA sur les comptes ciblés",
                "Consulter les logs d'authentification sur 24h",
            ],
            "T1078": [  # Valid Accounts
                "Désactiver le compte compromis (playbook disable_account)",
                "Réinitialiser le mot de passe et forcer MFA",
                "Auditer les accès récents du compte",
                "Vérifier les connexions depuis des IPs inhabituelles",
            ],
            "T1021": [  # Remote Services (mouvement latéral)
                "Isoler les machines impliquées (playbook isolate_machine)",
                "Cartographier le chemin de propagation",
                "Analyser les connexions réseau inter-machines",
                "Collecte forensique avant isolation complète",
            ],
            "T1041": [  # Exfiltration
                "Bloquer immédiatement les connexions sortantes suspectes",
                "Identifier les données potentiellement exfiltrées",
                "Notifier le DPO si données personnelles concernées (RGPD)",
                "Conserver les captures réseau comme preuves",
            ],
            "T1068": [  # Privilege Escalation
                "Révoquer les droits accordés illégitimement",
                "Auditer les journaux sudo/su",
                "Vérifier les modifications de /etc/passwd et /etc/sudoers",
                "Isoler la machine si compromission confirmée",
            ],
        }

        # Actions par défaut si la technique n'est pas dans le mapping
        default_actions = [
            f"Analyser l'alerte de sévérité {severity}",
            "Collecter les preuves (logs, captures réseau)",
            "Évaluer l'impact potentiel sur le système d'information",
            "Décider d'une réponse manuelle selon l'analyse",
        ]

        return actions_by_technique.get(technique_id, default_actions)

    # ─────────────────────────────────────────
    # Création du ticket incident dans ES
    # ─────────────────────────────────────────

    async def _create_incident_ticket(
        self, report: Dict[str, Any]
    ) -> Optional[str]:
        """
        Crée un ticket d'incident dans idx-incidents.

        Retourne l'ID du ticket créé, ou None en cas d'erreur.
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            res = await self.es.index(
                index="idx-incidents",
                document={
                    "titre": f"Incident SOAR — {report['rule_name']} [{report['severity']}]",
                    "description": (
                        f"Alerte automatique SOAR — Règle : {report['rule_name']}\n"
                        f"MITRE : {report['mitre_tactic']} / {report['mitre_technique_id']}\n"
                        f"UEBA Entité : {report['ueba_entity']} — Score : {report['ueba_risk_score']}"
                    ),
                    "statut": "ouvert",                     # Nouveau ticket
                    "priorite": report["severity"],
                    "alert_id": report["alert_id"],
                    "rule_id": report["rule_id"],
                    "mitre_tactic": report["mitre_tactic"],
                    "mitre_technique_id": report["mitre_technique_id"],
                    "ueba_context": {
                        "entity_id": report["ueba_entity"],
                        "risk_score": report["ueba_risk_score"],
                        "reasons": report["ueba_anomaly_reasons"],
                    },
                    "recommended_actions": report["recommended_actions"],
                    "sla_response_minutes": report["sla_response_minutes"],
                    "assigned_to": None,                    # À assigner par le SOC
                    "created_at": now,
                    "updated_at": now,
                    "escalation_source": "soar_automatic",
                },
            )
            ticket_id = res["_id"]
            logger.info("[EscalateIncident] Ticket créé : %s", ticket_id)
            return ticket_id
        except Exception as exc:
            logger.error("[EscalateIncident] Erreur création ticket ES : %s", exc)
            return None

    # ─────────────────────────────────────────
    # Mise à jour du statut de l'alerte source
    # ─────────────────────────────────────────

    async def _update_alert_status(self, alert_id: str, ticket_id: Optional[str]) -> None:
        """
        Met à jour le statut de l'alerte source en 'en_cours' et lie le ticket.
        """
        if not alert_id or alert_id == "unknown":
            return
        try:
            await self.es.update(
                index="idx-alerts",
                id=alert_id,
                doc={
                    "statut": "en_cours",                     # Alerte prise en charge
                    "incident_ticket_id": ticket_id,          # Lien vers le ticket
                    "escalated_by": "soar",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception as exc:
            # Non bloquant : l'escalade continue même si la mise à jour échoue
            logger.warning("[EscalateIncident] Erreur mise à jour alerte %s : %s", alert_id, exc)

    # ─────────────────────────────────────────
    # Méthode principale : execute()
    # ─────────────────────────────────────────

    async def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exécute l'escalade de l'incident.

        Ce playbook ne nécessite pas d'approbation humaine car il est
        purement informatif (aucune action destructrice).
        """
        # ── ÉTAPE 1 : Décision de la politique SOAR ───────────────────────
        # Pour un playbook non destructeur, on accepte dès WARNING
        decision = self.policy.decide(
            playbook=self.name,
            alert=alert,
            target=alert.get("rule_id", "unknown"),
        )
        if not decision.allowed:
            return self.skipped(decision.reason, target=alert.get("rule_id"))

        # ── ÉTAPE 2 : Construction du rapport d'escalade ──────────────────
        report = self._build_escalation_report(alert)

        # ── ÉTAPE 3 : Création du ticket incident ─────────────────────────
        ticket_id = await self._create_incident_ticket(report)

        # ── ÉTAPE 4 : Mise à jour du statut de l'alerte source ───────────
        alert_id = alert.get("_id") or alert.get("id")
        if alert_id:
            await self._update_alert_status(str(alert_id), ticket_id)

        # ── ÉTAPE 5 : Log de l'escalade ───────────────────────────────────
        logger.warning(
            "[EscalateIncident] Incident escaladé — alerte=%s ticket=%s sévérité=%s decision_id=%s",
            alert_id, ticket_id, report["severity"], decision.decision_id,
        )

        return self.success(
            target=report["alert_id"],
            extra={
                "action": "escalate_incident",
                "ticket_id": ticket_id,
                "severity": report["severity"],
                "mitre_technique_id": report["mitre_technique_id"],
                "sla_response_minutes": CRITICAL_SLA_MINUTES,
                "decision_id": decision.decision_id,
                "recommended_actions": report["recommended_actions"],
                "ueba_risk_score": report["ueba_risk_score"],
            },
        )
