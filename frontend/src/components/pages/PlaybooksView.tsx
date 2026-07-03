/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from "react";
import {
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Server,
  Terminal,
  RefreshCw,
  Clock,
  Briefcase,
  ListOrdered,
  Code,
  Target,
  Zap,
} from "lucide-react";
import api from "../../Services/api";
import type { Playbook, UserRole } from "../../types";
import { RBAC_POLICIES } from "../../utils/rbac";

interface PlaybooksViewProps {
  activeRole: UserRole;
}

const PLAYBOOKS_FALLBACK: Playbook[] = [
  {
    id: "pb-001",
    name: "Blocage IP automatique (pfSense)",
    description:
      "Bloque automatiquement l'adresse IP source via pfSense (SSH + paramiko). " +
      "Déclenché dès détection d'une alerte HIGH/CRITICAL contenant un source_ip. " +
      "Commande : pfctl -t blocklist -T add {ip} sur 192.168.100.254.",
    action_type: "block_ip",
    execution_mode: "AUTO",
    parameters: {
      method: "pfSense SSH (paramiko)",
      command: "pfctl -t blocklist -T add {ip}",
      trigger: "Alerte HIGH/CRITICAL avec source_ip",
      firewall_host: "192.168.100.254",
    },
    target_type: "ip_address",
    confirmation_timeout_seconds: 0,
    is_active: true,
    execution_count: 0,
    last_executed_at: null,
    created_by: "system",
  },
  {
    id: "pb-002",
    name: "Désactivation compte Active Directory",
    description:
      "Désactive un compte utilisateur compromis via LDAP3 sur le contrôleur de domaine (port 389). " +
      "Mode CONFIRM : un analyste doit valider dans les 60 secondes. " +
      "Déclenché sur détection de mouvement latéral ou compromission de compte.",
    action_type: "disable_account",
    execution_mode: "CONFIRM",
    parameters: {
      method: "LDAP3 disable_account",
      ldap_port: 389,
      trigger: "Compromission de compte (mouvement latéral)",
      timeout_confirmation_s: 60,
    },
    target_type: "user_account",
    confirmation_timeout_seconds: 60,
    is_active: true,
    execution_count: 0,
    last_executed_at: null,
    created_by: "system",
  },
  {
    id: "pb-003",
    name: "Escalade incident — Alerte critique",
    description:
      "Crée un ticket d'incident et envoie une notification d'escalade immédiate " +
      "quand une alerte CRITICAL reste non résolue. " +
      "Canaux : email + Slack. Déclenché par le moteur de corrélation.",
    action_type: "notify_escalation",
    execution_mode: "CONFIRM",
    parameters: {
      method: "notification + ticket ITSM",
      trigger: "Alerte CRITICAL non résolue",
      channels: ["email", "slack"],
      ticket_system: "interne",
    },
    target_type: null,
    confirmation_timeout_seconds: 300,
    is_active: true,
    execution_count: 0,
    last_executed_at: null,
    created_by: "system",
  },
];

const ACTION_TYPE_LABELS: Record<string, string> = {
  block_ip: "Bloquer IP",
  disable_account: "Désactiver compte",
  isolate_machine: "Isoler machine",
  notify_escalation: "Notifier escalade",
  collect_evidence: "Collecter preuves",
};

const ACTION_TYPE_ICONS: Record<string, React.ReactNode> = {
  block_ip: <XCircle className="w-4 h-4" />,
  disable_account: <AlertTriangle className="w-4 h-4" />,
  isolate_machine: <Server className="w-4 h-4" />,
  notify_escalation: <Terminal className="w-4 h-4" />,
  collect_evidence: <ListOrdered className="w-4 h-4" />,
};

export default function PlaybooksView({ activeRole }: PlaybooksViewProps) {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loading, setLoading] = useState(true);
  const [runningPlaybookId, setRunningPlaybookId] = useState<string | null>(
    null,
  );

  const canTrigger = RBAC_POLICIES[activeRole].canTriggerPlaybook;

  useEffect(() => {
    async function loadPlaybooks() {
      try {
        const res = await api.getPlaybooks();
        setPlaybooks(res.length > 0 ? res : PLAYBOOKS_FALLBACK);
      } catch {
        setPlaybooks(PLAYBOOKS_FALLBACK);
      } finally {
        setLoading(false);
      }
    }
    loadPlaybooks();
  }, []);

  const handleTrigger = async (id: string) => {
    if (!canTrigger) return;
    setRunningPlaybookId(id);

    try {
      // Simulate orchestration latency
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const updated = await api.triggerPlaybook(id, "Dominique", activeRole);
      setPlaybooks((prev) => prev.map((p) => (p.id === id ? updated : p)));
    } catch (err) {
      console.error("Erreur exécution playbook", err);
    } finally {
      setRunningPlaybookId(null);
    }
  };

  if (loading) {
    return (
      <div
        id="playbooks-loading"
        className="flex-1 flex items-center justify-center p-8 h-full"
      >
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div
      id="playbooks-view"
      className="p-6 space-y-6 overflow-y-auto h-full pb-16"
    >
      {/* Header Description */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Briefcase className="w-4.5 h-4.5 text-blue-600 dark:text-blue-400" />
            <span>Automatisation & Orchestration SOAR (Playbooks)</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Orchestrez et automatisez des réponses aux incidents sur vos
            infrastructures de manière instantanée et sécurisée.
          </p>
        </div>
      </div>

      {/* Grid displays */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {playbooks.map((play) => {
          const isRunning = runningPlaybookId === play.id;
          const isAuto = play.execution_mode === "AUTO";

          return (
            <div
              key={play.id}
              className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between gap-5 hover:scale-[1.005] transition-all relative overflow-hidden"
            >
              <div className="space-y-4">
                {/* Top header details */}
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                      {play.id}
                    </span>
                    <h5 className="font-bold text-sm text-slate-900 dark:text-slate-100 leading-tight">
                      {play.name}
                    </h5>
                  </div>

                  <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-slate-400">
                    <Clock className="w-3.5 h-3.5" />
                    <span>{play.execution_count} exécutions</span>
                  </div>
                </div>

                <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                  {play.description}
                </p>

                {/* Action type & Execution mode badges */}
                <div className="flex flex-wrap items-center gap-2">
                  <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
                    {ACTION_TYPE_ICONS[play.action_type]}
                    <span>
                      {ACTION_TYPE_LABELS[play.action_type] || play.action_type}
                    </span>
                  </div>

                  <div
                    className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono border ${
                      isAuto
                        ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20"
                        : "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20"
                    }`}
                  >
                    <Zap
                      className={`w-3 h-3 ${isAuto ? "text-emerald-500" : "text-amber-500"}`}
                    />
                    <span>{isAuto ? "AUTO" : "CONFIRM"}</span>
                  </div>

                  {play.target_type && (
                    <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                      <Target className="w-3 h-3" />
                      <span>Cible: {play.target_type.replace("_", " ")}</span>
                    </div>
                  )}
                </div>

                {/* Parameters JSON display */}
                {Object.keys(play.parameters).length > 0 && (
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                      <Code className="w-3.5 h-3.5 text-blue-500" />
                      <span>PARAMÈTRES</span>
                    </div>
                    <div className="bg-slate-50 dark:bg-slate-950 p-2 rounded border border-slate-200 dark:border-slate-800 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      <pre className="whitespace-pre-wrap">
                        {JSON.stringify(play.parameters, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>

              {/* Action Trigger line */}
              <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800/60 pt-4 mt-2 font-mono text-[10px] text-slate-400">
                <div>
                  {play.last_executed_at ? (
                    <span>
                      Lancé le:{" "}
                      {new Date(play.last_executed_at).toLocaleString()}
                    </span>
                  ) : (
                    <span className="italic">Jamais déclenché</span>
                  )}
                </div>

                <button
                  onClick={() => handleTrigger(play.id)}
                  disabled={!canTrigger || isRunning}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs font-sans transition-all active:scale-95 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-md hover:shadow-blue-500/20"
                >
                  {isRunning ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Exécution...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Lancer le playbook</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
