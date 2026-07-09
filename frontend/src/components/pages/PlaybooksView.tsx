/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState, useCallback } from "react";
import {
  Play,
  Plus,
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
  Shield,
  ShieldOff,
  UserX,
  Unlock,
  UserCheck,
  ChevronDown,
  ChevronUp,
  Ban,
  History,
  CheckCircle2,
  X,
  Pencil,
} from "lucide-react";
import api from "../../Services/api";
import type { SoarHistoryEntry } from "../../Services/soarService";
import type { Playbook, UserRole } from "../../types";
import { RBAC_POLICIES } from "../../utils/rbac";

interface PlaybooksViewProps {
  activeRole: UserRole;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const ACTION_TYPE_OPTIONS = [
  { value: "block_ip",          label: "Bloquer IP (pfSense)" },
  { value: "disable_account",   label: "Désactiver compte (AD)" },
  { value: "isolate_machine",   label: "Isoler machine" },
  { value: "notify_escalation", label: "Notification / Escalade" },
  { value: "collect_evidence",  label: "Collecte de preuves" },
  { value: "custom",            label: "Personnalisé" },
] as const;

const DEFAULT_PARAMS: Record<string, object> = {
  block_ip:          { firewall: "pfSense", host: "192.168.100.254" },
  disable_account:   { ldap_host: "192.168.100.5", ldap_port: 389, domain: "ctu.local" },
  isolate_machine:   { method: "network_isolation" },
  notify_escalation: { channels: ["email"], ticket_system: "interne" },
  collect_evidence:  { formats: ["pcap", "logs"] },
  custom:            {},
};

const ACTION_LABELS: Record<string, string> = {
  block_ip:          "IP bloquée",
  unblock_ip:        "IP débloquée",
  disable_account:   "Compte désactivé",
  enable_account:    "Compte réactivé",
  notify_escalation: "Escalade",
  isolate_machine:   "Machine isolée",
  collect_evidence:  "Preuves collectées",
};

const ACTION_COLORS: Record<string, string> = {
  block_ip:          "text-red-500 bg-red-500/10",
  unblock_ip:        "text-emerald-500 bg-emerald-500/10",
  disable_account:   "text-amber-500 bg-amber-500/10",
  enable_account:    "text-emerald-500 bg-emerald-500/10",
  notify_escalation: "text-blue-500 bg-blue-500/10",
  isolate_machine:   "text-purple-500 bg-purple-500/10",
  collect_evidence:  "text-cyan-500 bg-cyan-500/10",
};

const ACTION_TYPE_ICONS: Record<string, React.ReactNode> = {
  block_ip:          <ShieldOff className="w-3.5 h-3.5" />,
  disable_account:   <UserX className="w-3.5 h-3.5" />,
  isolate_machine:   <Server className="w-3.5 h-3.5" />,
  notify_escalation: <Terminal className="w-3.5 h-3.5" />,
  collect_evidence:  <ListOrdered className="w-3.5 h-3.5" />,
  custom:            <Code className="w-3.5 h-3.5" />,
};

const PLAYBOOKS_FALLBACK: Playbook[] = [
  {
    id: "pb-001",
    name: "Blocage IP automatique (pfSense)",
    description: "Bloque l'IP source malveillante via pfSense SSH (pfctl -t blocklist -T add).",
    action_type: "block_ip",
    execution_mode: "AUTO",
    parameters: { method: "pfSense SSH (paramiko)", command: "pfctl -t blocklist -T add {ip}", firewall_host: "192.168.100.254" },
    target_type: "ip_address",
    confirmation_timeout_seconds: 1,
    is_active: true,
    execution_count: 0,
    last_executed_at: null,
    created_by: "system",
  },
  {
    id: "pb-002",
    name: "Désactivation compte Active Directory",
    description: "Désactive un compte AD compromis via LDAP3. Mode CONFIRM — validation analyste requise.",
    action_type: "disable_account",
    execution_mode: "CONFIRM",
    parameters: { method: "LDAP3 disable_account", ldap_port: 389, timeout_confirmation_s: 60 },
    target_type: "user_account",
    confirmation_timeout_seconds: 60,
    is_active: true,
    execution_count: 0,
    last_executed_at: null,
    created_by: "system",
  },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("fr-FR", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

// ── Default new playbook form state ────────────────────────────────────────────

function defaultForm() {
  return {
    name: "",
    description: "",
    action_type: "block_ip",
    execution_mode: "CONFIRM",
    confirmation_timeout_seconds: 300,
    parameters: JSON.stringify(DEFAULT_PARAMS["block_ip"], null, 2),
    rollback_supported: false,
    target_type: "",
    is_active: true,
  };
}

// ── Modal backdrop ─────────────────────────────────────────────────────────────

function Backdrop({ onClose }: { onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    />
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function PlaybooksView({ activeRole }: PlaybooksViewProps) {
  const canTrigger = RBAC_POLICIES[activeRole].canTriggerPlaybook;
  const isAdmin = activeRole === "admin";

  // — Data states —
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [history, setHistory] = useState<SoarHistoryEntry[]>([]);
  const [loadingPlaybooks, setLoadingPlaybooks] = useState(true);
  const [loadingHistory, setLoadingHistory] = useState(true);

  // — Accordion —
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // — Toast —
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" } | null>(null);

  // — Modal: Block IP —
  const [blockModal, setBlockModal] = useState({ open: false, ip: "", loading: false });

  // — Modal: Disable Account —
  const [disableModal, setDisableModal] = useState({ open: false, username: "", loading: false });

  // — Modal: New Playbook —
  const [newPbModal, setNewPbModal] = useState({ open: false, loading: false, form: defaultForm() });

  // — Modal: Launch Playbook —
  const [launchModal, setLaunchModal] = useState<{
    open: boolean; playbook: Playbook | null; target: string; loading: boolean;
  }>({ open: false, playbook: null, target: "", loading: false });

  const showToast = useCallback((msg: string, type: "success" | "error") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 4000);
  }, []);

  // Load playbooks
  const loadPlaybooks = useCallback(async () => {
    setLoadingPlaybooks(true);
    try {
      const res = await api.getPlaybooks();
      setPlaybooks(res.length > 0 ? res : PLAYBOOKS_FALLBACK);
    } catch {
      setPlaybooks(PLAYBOOKS_FALLBACK);
    } finally {
      setLoadingPlaybooks(false);
    }
  }, []);

  // Load history
  const loadHistory = useCallback(async () => {
    setLoadingHistory(true);
    try {
      const res = await api.getSoarHistory();
      setHistory(res);
    } catch {
      setHistory([]);
    } finally {
      setLoadingHistory(false);
    }
  }, []);

  useEffect(() => {
    loadPlaybooks();
    loadHistory();
  }, [loadPlaybooks, loadHistory]);

  // ── Actions ──────────────────────────────────────────────────────────────────

  const handleBlockIp = async () => {
    const ip = blockModal.ip.trim();
    if (!ip) return;
    setBlockModal((s) => ({ ...s, loading: true }));
    try {
      await api.soarBlockIp(ip);
      showToast(`IP ${ip} bloquée avec succès`, "success");
      setBlockModal({ open: false, ip: "", loading: false });
      loadHistory();
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      showToast(msg || `Erreur lors du blocage de ${ip}`, "error");
      setBlockModal((s) => ({ ...s, loading: false }));
    }
  };

  const handleDisableAccount = async () => {
    const username = disableModal.username.trim();
    if (!username) return;
    setDisableModal((s) => ({ ...s, loading: true }));
    try {
      await api.soarDisableAccount(username);
      showToast(`Compte ${username} désactivé avec succès`, "success");
      setDisableModal({ open: false, username: "", loading: false });
      loadHistory();
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      showToast(msg || `Erreur lors de la désactivation de ${username}`, "error");
      setDisableModal((s) => ({ ...s, loading: false }));
    }
  };

  const handleCreatePlaybook = async () => {
    const f = newPbModal.form;
    let params: object = {};
    try {
      params = JSON.parse(f.parameters);
    } catch {
      showToast("Paramètres JSON invalides", "error");
      return;
    }
    setNewPbModal((s) => ({ ...s, loading: true }));
    try {
      const created = await api.createPlaybook({
        name: f.name,
        description: f.description,
        action_type: f.action_type,
        execution_mode: f.execution_mode,
        confirmation_timeout_seconds: Math.max(1, f.confirmation_timeout_seconds),
        parameters: params,
        rollback_supported: f.rollback_supported,
        target_type: f.target_type || null,
        is_active: f.is_active,
      });
      showToast(`Playbook "${created.name}" créé`, "success");
      setNewPbModal({ open: false, loading: false, form: defaultForm() });
      loadPlaybooks();
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      showToast(msg || "Erreur lors de la création", "error");
      setNewPbModal((s) => ({ ...s, loading: false }));
    }
  };

  const handleLaunch = async () => {
    const pb = launchModal.playbook;
    if (!pb) return;
    setLaunchModal((s) => ({ ...s, loading: true }));
    try {
      if (pb.action_type === "block_ip") {
        await api.soarBlockIp(launchModal.target.trim());
        showToast(`IP ${launchModal.target} bloquée`, "success");
      } else if (pb.action_type === "disable_account") {
        await api.soarDisableAccount(launchModal.target.trim());
        showToast(`Compte ${launchModal.target} désactivé`, "success");
      } else {
        await api.triggerPlaybook(pb.id, "analyst", activeRole);
        showToast(`Playbook "${pb.name}" déclenché`, "success");
      }
      setLaunchModal({ open: false, playbook: null, target: "", loading: false });
      loadHistory();
      loadPlaybooks();
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      showToast(msg || "Erreur lors du déclenchement", "error");
      setLaunchModal((s) => ({ ...s, loading: false }));
    }
  };

  const handleReverseAction = async (entry: SoarHistoryEntry) => {
    try {
      if (entry.action === "block_ip") {
        await api.unblockIp(entry.target);
        showToast(`IP ${entry.target} débloquée`, "success");
      } else if (entry.action === "disable_account") {
        await api.enableAccount(entry.target);
        showToast(`Compte ${entry.target} réactivé`, "success");
      }
      loadHistory();
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      showToast(msg || "Erreur lors de l'action inverse", "error");
    }
  };

  const toggleAccordion = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  // ── New Playbook form helpers ──────────────────────────────────────────────

  const updateForm = (patch: Partial<typeof newPbModal.form>) => {
    setNewPbModal((s) => ({ ...s, form: { ...s.form, ...patch } }));
  };

  const onActionTypeChange = (v: string) => {
    updateForm({
      action_type: v,
      parameters: JSON.stringify(DEFAULT_PARAMS[v] ?? {}, null, 2),
    });
  };

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <div id="playbooks-view" className="p-6 space-y-6 overflow-y-auto h-full pb-20 relative">

      {/* Toast */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-xl shadow-xl text-sm font-semibold flex items-center gap-2 transition-all animate-in slide-in-from-top-2 ${
          toast.type === "success" ? "bg-emerald-600 text-white" : "bg-red-600 text-white"
        }`}>
          {toast.type === "success" ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          {toast.msg}
        </div>
      )}

      {/* ── Section 1 : Header + Actions rapides ── */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Briefcase className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              Automatisation & Orchestration SOAR
            </h4>
            <p className="text-xs text-slate-400 dark:text-slate-500">
              Actions rapides de remédiation et gestion des playbooks de sécurité.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setBlockModal({ open: true, ip: "", loading: false })}
              disabled={!canTrigger}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold disabled:opacity-40 transition-all shadow-sm"
            >
              <Ban className="w-3.5 h-3.5" />
              Bloquer une IP
            </button>
            <button
              onClick={() => setDisableModal({ open: true, username: "", loading: false })}
              disabled={!canTrigger}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold disabled:opacity-40 transition-all shadow-sm"
            >
              <UserX className="w-3.5 h-3.5" />
              Désactiver un compte
            </button>
            {isAdmin && (
              <button
                onClick={() => setNewPbModal({ open: true, loading: false, form: defaultForm() })}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition-all shadow-sm"
              >
                <Plus className="w-3.5 h-3.5" />
                Nouveau playbook
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── Section 2 : Historique SOAR ── */}
      <div className="bg-white dark:bg-[#1E293B] rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-blue-500" />
            <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">
              Historique des actions SOAR
            </span>
            {!loadingHistory && (
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-blue-500/10 text-blue-500">
                {history.length}
              </span>
            )}
          </div>
          <button
            onClick={loadHistory}
            disabled={loadingHistory}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-500 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingHistory ? "animate-spin" : ""}`} />
            Actualiser
          </button>
        </div>

        {loadingHistory ? (
          <div className="flex items-center justify-center py-12">
            <div className="w-7 h-7 border-4 border-blue-600 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : history.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-14 gap-3 text-slate-400">
            <History className="w-10 h-10 opacity-20" />
            <p className="text-sm">Aucune action SOAR enregistrée</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="bg-slate-50 dark:bg-slate-800/50 text-slate-400 text-left">
                  <th className="px-4 py-3 font-semibold">Horodatage</th>
                  <th className="px-4 py-3 font-semibold">Action</th>
                  <th className="px-4 py-3 font-semibold">Cible</th>
                  <th className="px-4 py-3 font-semibold">Résultat</th>
                  <th className="px-4 py-3 font-semibold text-right">Inverser</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {history.map((entry) => (
                  <tr key={entry.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {fmtDate(entry.executed_at)}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold ${ACTION_COLORS[entry.action] ?? "text-slate-500 bg-slate-100 dark:bg-slate-800"}`}>
                        {entry.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-bold text-slate-700 dark:text-slate-200">
                      {entry.target}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] font-bold ${
                        entry.status === "success" ? "text-emerald-500" :
                        entry.status === "failed"  ? "text-red-500"     :
                        entry.status === "pending" ? "text-amber-500"   : "text-slate-400"
                      }`}>
                        {entry.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      {entry.action === "block_ip" && entry.status === "success" ? (
                        <button
                          onClick={() => handleReverseAction(entry)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 font-semibold text-[10px] ml-auto transition-all"
                        >
                          <Unlock className="w-3 h-3" />
                          Débloquer
                        </button>
                      ) : entry.action === "disable_account" && entry.status === "success" ? (
                        <button
                          onClick={() => handleReverseAction(entry)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 font-semibold text-[10px] ml-auto transition-all"
                        >
                          <UserCheck className="w-3 h-3" />
                          Réactiver
                        </button>
                      ) : (
                        <span className="text-slate-300 dark:text-slate-700 text-xs select-none">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Section 3 : Playbooks configurés (accordéon) ── */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 px-1">
          <Zap className="w-4 h-4 text-blue-500" />
          <h5 className="font-semibold text-sm text-slate-900 dark:text-slate-100">
            Playbooks configurés
          </h5>
          {!loadingPlaybooks && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-slate-100 dark:bg-slate-800 text-slate-500">
              {playbooks.length}
            </span>
          )}
        </div>

        {loadingPlaybooks ? (
          <div className="flex items-center justify-center py-12">
            <div className="w-7 h-7 border-4 border-blue-600 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : (
          playbooks.map((play) => {
            const isOpen = expanded.has(play.id);
            const isAuto = play.execution_mode === "AUTO";

            return (
              <div key={play.id} className="bg-white dark:bg-[#1E293B] rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden">
                {/* Accordion header — div instead of button to avoid nested <button> */}
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => toggleAccordion(play.id)}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") toggleAccordion(play.id); }}
                  className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`p-1.5 rounded-lg ${isAuto ? "bg-emerald-500/10" : "bg-amber-500/10"}`}>
                      {ACTION_TYPE_ICONS[play.action_type] ?? <Zap className="w-3.5 h-3.5" />}
                    </div>
                    <div className="min-w-0">
                      <p className="font-semibold text-sm text-slate-900 dark:text-slate-100 truncate">
                        {play.name}
                      </p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className={`text-[10px] font-bold font-mono px-1.5 py-0.5 rounded ${
                          isAuto
                            ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                            : "bg-amber-500/10 text-amber-600 dark:text-amber-400"
                        }`}>
                          {isAuto ? "AUTO" : "CONFIRM"}
                        </span>
                        <span className="text-[10px] text-slate-400 font-mono flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {play.execution_count} exéc.
                        </span>
                        {play.last_executed_at && (
                          <span className="text-[10px] text-slate-400 font-mono hidden sm:inline">
                            dernier: {fmtDate(play.last_executed_at)}
                          </span>
                        )}
                        <span className={`text-[10px] font-bold ${play.is_active ? "text-emerald-500" : "text-slate-400"}`}>
                          {play.is_active ? "● actif" : "○ inactif"}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-3 flex-shrink-0">
                    {canTrigger && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setLaunchModal({ open: true, playbook: play, target: "", loading: false });
                        }}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition-all"
                      >
                        <Play className="w-3 h-3 fill-current" />
                        Lancer
                      </button>
                    )}
                    {isAdmin && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setNewPbModal({
                            open: true,
                            loading: false,
                            form: {
                              name: play.name,
                              description: play.description ?? "",
                              action_type: play.action_type,
                              execution_mode: play.execution_mode,
                              confirmation_timeout_seconds: play.confirmation_timeout_seconds ?? 300,
                              parameters: JSON.stringify(play.parameters, null, 2),
                              rollback_supported: false,
                              target_type: play.target_type ?? "",
                              is_active: play.is_active,
                            },
                          });
                        }}
                        className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-all"
                        title="Modifier"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                    )}
                    {isOpen ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                  </div>
                </div>

                {/* Accordion body */}
                {isOpen && (
                  <div className="px-5 pb-5 space-y-4 border-t border-slate-100 dark:border-slate-800 pt-4">
                    <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                      {play.description}
                    </p>

                    <div className="flex flex-wrap gap-2">
                      <span className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
                        {ACTION_TYPE_ICONS[play.action_type]}
                        {ACTION_TYPE_OPTIONS.find((o) => o.value === play.action_type)?.label ?? play.action_type}
                      </span>
                      {play.target_type && (
                        <span className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                          <Target className="w-3 h-3" />
                          {play.target_type.replace(/_/g, " ")}
                        </span>
                      )}
                    </div>

                    {play.parameters && Object.keys(play.parameters).length > 0 && (
                      <div>
                        <p className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider mb-1 flex items-center gap-1">
                          <Code className="w-3 h-3 text-blue-500" /> PARAMÈTRES
                        </p>
                        <div className="bg-slate-50 dark:bg-slate-950 p-2.5 rounded border border-slate-200 dark:border-slate-800 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                          <pre className="whitespace-pre-wrap">{JSON.stringify(play.parameters, null, 2)}</pre>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* ══════════════════════════════════════════════════════════
          MODALS
      ══════════════════════════════════════════════════════════ */}

      {/* Modal: Bloquer une IP */}
      {blockModal.open && (
        <>
          <Backdrop onClose={() => setBlockModal({ open: false, ip: "", loading: false })} />
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="bg-white dark:bg-[#1E293B] rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 w-full max-w-sm p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="font-bold text-base text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Ban className="w-4 h-4 text-red-500" />
                  Bloquer une IP
                </h3>
                <button onClick={() => setBlockModal({ open: false, ip: "", loading: false })} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                L'adresse IP sera ajoutée à la blocklist pfSense via SSH.
              </p>
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Adresse IP *
                </label>
                <input
                  type="text"
                  value={blockModal.ip}
                  onChange={(e) => setBlockModal((s) => ({ ...s, ip: e.target.value }))}
                  onKeyDown={(e) => e.key === "Enter" && handleBlockIp()}
                  placeholder="ex: 192.168.1.42"
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 font-mono focus:outline-none focus:ring-2 focus:ring-red-500"
                  autoFocus
                />
              </div>
              <div className="flex gap-2 justify-end">
                <button
                  onClick={() => setBlockModal({ open: false, ip: "", loading: false })}
                  className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-all"
                >
                  Annuler
                </button>
                <button
                  onClick={handleBlockIp}
                  disabled={!blockModal.ip.trim() || blockModal.loading}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold disabled:opacity-50 transition-all"
                >
                  {blockModal.loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />}
                  Bloquer
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Modal: Désactiver un compte */}
      {disableModal.open && (
        <>
          <Backdrop onClose={() => setDisableModal({ open: false, username: "", loading: false })} />
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="bg-white dark:bg-[#1E293B] rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 w-full max-w-sm p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="font-bold text-base text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <UserX className="w-4 h-4 text-amber-500" />
                  Désactiver un compte
                </h3>
                <button onClick={() => setDisableModal({ open: false, username: "", loading: false })} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Le compte sera désactivé sur l'Active Directory via LDAP3.
              </p>
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Nom d'utilisateur *
                </label>
                <input
                  type="text"
                  value={disableModal.username}
                  onChange={(e) => setDisableModal((s) => ({ ...s, username: e.target.value }))}
                  onKeyDown={(e) => e.key === "Enter" && handleDisableAccount()}
                  placeholder="ex: jean.dupont"
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 font-mono focus:outline-none focus:ring-2 focus:ring-amber-500"
                  autoFocus
                />
              </div>
              <div className="flex gap-2 justify-end">
                <button
                  onClick={() => setDisableModal({ open: false, username: "", loading: false })}
                  className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-all"
                >
                  Annuler
                </button>
                <button
                  onClick={handleDisableAccount}
                  disabled={!disableModal.username.trim() || disableModal.loading}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold disabled:opacity-50 transition-all"
                >
                  {disableModal.loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <UserX className="w-3.5 h-3.5" />}
                  Désactiver
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Modal: Lancer un playbook */}
      {launchModal.open && launchModal.playbook && (
        <>
          <Backdrop onClose={() => setLaunchModal({ open: false, playbook: null, target: "", loading: false })} />
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="bg-white dark:bg-[#1E293B] rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 w-full max-w-sm p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="font-bold text-base text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Play className="w-4 h-4 fill-current text-blue-500" />
                  {launchModal.playbook.name}
                </h3>
                <button onClick={() => setLaunchModal({ open: false, playbook: null, target: "", loading: false })} className="text-slate-400 hover:text-slate-600">
                  <X className="w-4 h-4" />
                </button>
              </div>
              {(launchModal.playbook.action_type === "block_ip" || launchModal.playbook.action_type === "disable_account") ? (
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    {launchModal.playbook.action_type === "block_ip" ? "Adresse IP *" : "Nom d'utilisateur *"}
                  </label>
                  <input
                    type="text"
                    value={launchModal.target}
                    onChange={(e) => setLaunchModal((s) => ({ ...s, target: e.target.value }))}
                    onKeyDown={(e) => e.key === "Enter" && handleLaunch()}
                    placeholder={launchModal.playbook.action_type === "block_ip" ? "ex: 10.0.0.42" : "ex: jean.dupont"}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 text-slate-900 dark:text-slate-100"
                    autoFocus
                  />
                </div>
              ) : (
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Ce playbook sera déclenché immédiatement. Confirmer ?
                </p>
              )}
              <div className="flex gap-2 justify-end">
                <button
                  onClick={() => setLaunchModal({ open: false, playbook: null, target: "", loading: false })}
                  className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-all"
                >
                  Annuler
                </button>
                <button
                  onClick={handleLaunch}
                  disabled={
                    launchModal.loading ||
                    ((launchModal.playbook.action_type === "block_ip" || launchModal.playbook.action_type === "disable_account") && !launchModal.target.trim())
                  }
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition-all"
                >
                  {launchModal.loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                  Exécuter
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Modal: Nouveau playbook */}
      {newPbModal.open && (
        <>
          <Backdrop onClose={() => setNewPbModal((s) => ({ ...s, open: false }))} />
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="bg-white dark:bg-[#1E293B] rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
              <div className="sticky top-0 bg-white dark:bg-[#1E293B] flex items-center justify-between px-6 py-4 border-b border-slate-100 dark:border-slate-800 z-10">
                <h3 className="font-bold text-base text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Plus className="w-4 h-4 text-blue-500" />
                  Nouveau playbook
                </h3>
                <button onClick={() => setNewPbModal((s) => ({ ...s, open: false }))} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-6 space-y-5">
                {/* name */}
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Nom <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    maxLength={200}
                    value={newPbModal.form.name}
                    onChange={(e) => updateForm({ name: e.target.value })}
                    placeholder="ex: Blocage IP pfSense automatique"
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                {/* action_type */}
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Type d'action <span className="text-red-500">*</span>
                  </label>
                  <select
                    value={newPbModal.form.action_type}
                    onChange={(e) => onActionTypeChange(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    {ACTION_TYPE_OPTIONS.map((o) => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </select>
                </div>

                {/* execution_mode */}
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                    Mode d'exécution <span className="text-red-500">*</span>
                  </label>
                  <div className="flex gap-3">
                    {[
                      { v: "AUTO",    label: "Automatique (immédiat)", color: "emerald" },
                      { v: "CONFIRM", label: "Confirmation requise",   color: "amber"   },
                    ].map(({ v, label, color }) => (
                      <label key={v} className={`flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer text-xs font-semibold transition-all ${
                        newPbModal.form.execution_mode === v
                          ? color === "emerald"
                            ? "bg-emerald-500/10 border-emerald-500 text-emerald-600 dark:text-emerald-400"
                            : "bg-amber-500/10 border-amber-500 text-amber-600 dark:text-amber-400"
                          : "border-slate-300 dark:border-slate-600 text-slate-500"
                      }`}>
                        <input
                          type="radio"
                          name="exec_mode"
                          value={v}
                          checked={newPbModal.form.execution_mode === v}
                          onChange={() => updateForm({ execution_mode: v })}
                          className="sr-only"
                        />
                        {label}
                      </label>
                    ))}
                  </div>
                </div>

                {/* confirmation_timeout — visible uniquement en mode CONFIRM */}
                {newPbModal.form.execution_mode === "CONFIRM" && (
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      Délai de confirmation (secondes)
                    </label>
                    <input
                      type="number"
                      min={1}
                      value={newPbModal.form.confirmation_timeout_seconds}
                      onChange={(e) => updateForm({ confirmation_timeout_seconds: Number(e.target.value) })}
                      className="w-40 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                )}

                {/* parameters */}
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
                    <Code className="w-3 h-3" /> Paramètres (JSON)
                  </label>
                  <textarea
                    rows={5}
                    value={newPbModal.form.parameters}
                    onChange={(e) => updateForm({ parameters: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-slate-950 text-xs font-mono text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                    spellCheck={false}
                  />
                </div>

                {/* description */}
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Description
                  </label>
                  <textarea
                    rows={2}
                    value={newPbModal.form.description}
                    onChange={(e) => updateForm({ description: e.target.value })}
                    placeholder="Décrivez le rôle et le déclencheur de ce playbook..."
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                  />
                </div>

                {/* target_type */}
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Type de cible (optionnel)
                  </label>
                  <input
                    type="text"
                    maxLength={50}
                    value={newPbModal.form.target_type}
                    onChange={(e) => updateForm({ target_type: e.target.value })}
                    placeholder="ip_address | user_account | machine | subnet"
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-sm font-mono text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                {/* rollback_supported + is_active */}
                <div className="flex gap-6">
                  <label className="flex items-center gap-2 cursor-pointer text-xs font-semibold text-slate-700 dark:text-slate-300">
                    <input
                      type="checkbox"
                      checked={newPbModal.form.rollback_supported}
                      onChange={(e) => updateForm({ rollback_supported: e.target.checked })}
                      className="w-4 h-4 rounded accent-blue-600"
                    />
                    Rollback supporté
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-xs font-semibold text-slate-700 dark:text-slate-300">
                    <input
                      type="checkbox"
                      checked={newPbModal.form.is_active}
                      onChange={(e) => updateForm({ is_active: e.target.checked })}
                      className="w-4 h-4 rounded accent-blue-600"
                    />
                    Actif
                  </label>
                </div>
              </div>

              <div className="sticky bottom-0 bg-white dark:bg-[#1E293B] flex gap-2 justify-end px-6 py-4 border-t border-slate-100 dark:border-slate-800">
                <button
                  onClick={() => setNewPbModal((s) => ({ ...s, open: false }))}
                  className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-all"
                >
                  Annuler
                </button>
                <button
                  onClick={handleCreatePlaybook}
                  disabled={!newPbModal.form.name.trim() || newPbModal.loading}
                  className="flex items-center gap-1.5 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition-all"
                >
                  {newPbModal.loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                  Créer le playbook
                </button>
              </div>
            </div>
          </div>
        </>
      )}

    </div>
  );
}
