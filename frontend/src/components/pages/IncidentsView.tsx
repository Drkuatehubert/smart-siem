/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  Clock,
  User,
  CheckCircle,
  XCircle,
  AlertCircle,
  Briefcase,
  AlertTriangle,
  FileText,
  UserPlus,
  Zap,
  X,
} from "lucide-react";
import api from "../../Services/api";
import type { Incident, UserRole } from "../../types";
import { RBAC_POLICIES } from "../../utils/rbac";

interface IncidentsViewProps {
  activeRole: UserRole;
}

export default function IncidentsView({ activeRole }: IncidentsViewProps) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncId, setSelectedIncId] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" } | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  const showToast = (msg: string, type: "success" | "error" = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  // Load incidents
  useEffect(() => {
    async function loadIncidents() {
      try {
        const res = await api.getIncidents();
        setIncidents(res);
        if (res.length > 0) {
          setSelectedIncId(res[0].id);
        }
      } catch (err) {
        console.error("Erreur chargement incidents", err);
      } finally {
        setLoading(false);
      }
    }
    loadIncidents();
  }, []);

  const selectedIncident = incidents.find((i) => i.id === selectedIncId);

  // Can this role edit incidents?
  const canEdit = RBAC_POLICIES[activeRole].canEditIncidents;

  // Handle status update
  const handleStatusChange = async (newStatus: Incident["status"]) => {
    if (!selectedIncId) return;
    setActionLoading(true);
    try {
      await api.updateIncidentStatus(selectedIncId, newStatus, "Dominique", activeRole);
      setIncidents((prev) =>
        prev.map((inc) => inc.id === selectedIncId ? { ...inc, status: newStatus } : inc),
      );
      showToast("Statut mis à jour avec succès");
    } catch (err) {
      console.error("Erreur changement statut", err);
      showToast("Erreur lors de la mise à jour", "error");
    } finally {
      setActionLoading(false);
    }
  };

  // Handle assignment change
  const handleAssignChange = async (newAssignee: string) => {
    if (!selectedIncId) return;
    try {
      const updated = await api.assignIncident(
        selectedIncId,
        newAssignee,
        "Dominique",
        activeRole,
      );
      setIncidents((prev) =>
        prev.map((inc) => (inc.id === selectedIncId ? updated : inc)),
      );
    } catch (err) {
      console.error("Erreur assignation", err);
    }
  };

  if (loading) {
    return (
      <div
        id="incidents-loading"
        className="flex-1 flex items-center justify-center p-8 h-full"
      >
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  // Filtered incidents
  const filteredIncidents = incidents.filter((inc) => {
    const matchesStatus = statusFilter === "ALL" || inc.status === statusFilter;
    const matchesSeverity =
      severityFilter === "ALL" || inc.severity === severityFilter;
    return matchesStatus && matchesSeverity;
  });

  return (
    <div id="incidents-view" className="h-full flex overflow-hidden relative">
      {/* Toast notification */}
      {toast && (
        <div className={`absolute top-4 right-4 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl shadow-lg border text-sm font-semibold transition-all ${
          toast.type === "success"
            ? "bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300"
            : "bg-red-50 dark:bg-red-950/60 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300"
        }`}>
          {toast.type === "success"
            ? <CheckCircle className="w-4 h-4 shrink-0" />
            : <XCircle className="w-4 h-4 shrink-0" />}
          <span>{toast.msg}</span>
          <button onClick={() => setToast(null)} className="ml-1 opacity-60 hover:opacity-100">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
      {/* LEFT PANEL: Incidents list with Search & Filters */}
      <div className="w-80 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0b0f19] flex flex-col shrink-0 h-full">
        {/* Filters block */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <h4 className="font-bold text-xs uppercase text-slate-400 dark:text-slate-500 font-mono tracking-wider">
              FILTRER LES INCIDENTS
            </h4>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-slate-400 font-bold font-mono">
                STATUT
              </label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full mt-1 px-2.5 py-1.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
              >
                <option value="ALL">Tous</option>
                <option value="open">Ouvert</option>
                <option value="in_progress">En Cours</option>
                <option value="pending_action">Action Requise</option>
                <option value="resolved">Résolu</option>
                <option value="closed">Clos</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] text-slate-400 font-bold font-mono">
                SEVÉRITÉ
              </label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="w-full mt-1 px-2.5 py-1.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
              >
                <option value="ALL">Toutes</option>
                <option value="critical">Critique</option>
                <option value="high">Haute</option>
                <option value="warning">Moyenne</option>
                <option value="info">Basse</option>
              </select>
            </div>
          </div>
        </div>

        {/* Scrollable list of incidents */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/60">
          {filteredIncidents.length === 0 ? (
            <div className="p-6 text-center text-slate-400 dark:text-slate-500 font-medium text-xs">
              <ShieldAlert className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2" />
              <span>Aucun incident détecté</span>
            </div>
          ) : (
            filteredIncidents.map((inc) => {
              const isSelected = inc.id === selectedIncId;
              const sevColors =
                inc.severity === "critical"
                  ? "bg-red-500"
                  : inc.severity === "high"
                    ? "bg-orange-500"
                    : inc.severity === "warning"
                      ? "bg-amber-500"
                      : "bg-blue-500";

              const statusBadge =
                inc.status === "open"
                  ? "text-rose-500 border-rose-500/20 bg-rose-500/5"
                  : inc.status === "in_progress"
                    ? "text-amber-500 border-amber-500/20 bg-amber-500/5"
                    : inc.status === "pending_action"
                      ? "text-purple-500 border-purple-500/20 bg-purple-500/5"
                      : inc.status === "resolved"
                        ? "text-emerald-500 border-emerald-500/20 bg-emerald-500/5"
                        : "text-slate-400 border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/10";

              return (
                <button
                  key={inc.id}
                  onClick={() => setSelectedIncId(inc.id)}
                  className={`w-full text-left p-4 transition-all flex flex-col gap-2 relative border-l-4 border-transparent ${
                    isSelected
                      ? "bg-blue-50/40 dark:bg-blue-950/10 border-l-blue-600"
                      : "hover:bg-slate-50/50 dark:hover:bg-slate-900/10"
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                      {inc.id}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${statusBadge}`}
                    >
                      {inc.status}
                    </span>
                  </div>

                  <h5 className="font-bold text-xs text-slate-800 dark:text-slate-200 line-clamp-1">
                    {inc.title}
                  </h5>

                  <div className="flex items-center justify-between mt-1 text-[10px] text-slate-400 dark:text-slate-500 font-mono font-semibold">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`w-2.5 h-2.5 rounded-full ${sevColors}`}
                      ></span>
                      <span>Sévérité {inc.severity}</span>
                    </div>
                    <span>{inc.affected_assets.length} assets</span>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>

      {/* RIGHT PANEL: Incident Detail View */}
      <div className="flex-1 bg-slate-50 dark:bg-[#0F172A] flex flex-col h-full overflow-hidden">
        {selectedIncident ? (
          <div className="flex-1 flex flex-col h-full overflow-hidden">
            {/* Detail Header */}
            <div className="p-6 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-[#1E293B] shrink-0 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono font-extrabold text-blue-600 dark:text-blue-400">
                    {selectedIncident.id}
                  </span>
                  <span className="px-2.5 py-0.5 rounded-full bg-red-500/10 text-red-500 font-bold text-[10px] uppercase border border-red-500/20 font-mono">
                    {selectedIncident.severity}
                  </span>
                </div>

                {/* Edit options if user has permissions */}
                {canEdit ? (
                  <div className="flex items-center gap-3">
                    {/* Status Select */}
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-400" />
                      <select
                        value={selectedIncident.status}
                        onChange={(e) =>
                          handleStatusChange(
                            e.target.value as Incident["status"],
                          )
                        }
                        className="px-2.5 py-1.5 rounded-lg border text-xs bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none"
                      >
                        <option value="open">Ouvert</option>
                        <option value="in_progress">En Cours</option>
                        <option value="pending_action">Action Requise</option>
                        <option value="resolved">Résolu</option>
                        <option value="closed">Clos</option>
                      </select>
                    </div>

                    {/* Assignee Select */}
                    <div className="flex items-center gap-1.5">
                      <UserPlus className="w-3.5 h-3.5 text-slate-400" />
                      <select
                        value={selectedIncident.assigned_to || "Non assigné"}
                        onChange={(e) => handleAssignChange(e.target.value)}
                        className="px-2.5 py-1.5 rounded-lg border text-xs bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none"
                      >
                        <option value="Non assigné">Non assigné</option>
                        <option value="Analyste SOC 1">
                          Analyste SOC 1
                        </option>
                        <option value="Sophie Bernard (SOC)">
                          Sophie Bernard (SOC)
                        </option>
                        <option value="Dominique (SOC)">Dominique (SOC)</option>
                      </select>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-4 text-xs font-mono font-bold text-slate-450">
                    <div className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" />
                      <span>Statut: {selectedIncident.status}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <User className="w-3.5 h-3.5" />
                      <span>
                        Assigné: {selectedIncident.assigned_to || "Non assigné"}
                      </span>
                    </div>
                  </div>
                )}
              </div>

              <h3 className="text-lg font-bold text-slate-900 dark:text-slate-50 tracking-tight">
                {selectedIncident.title}
              </h3>
            </div>

            {/* Scrollable Contents: root cause, response actions, affected assets, IOC */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Quick action buttons */}
              {canEdit && (
                <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                  <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                    <Zap className="w-4 h-4 text-amber-500" />
                    Actions rapides
                  </h4>
                  {selectedIncident.alert_title && (
                    <p className="text-[10px] font-mono text-slate-400">
                      Alerte source :{" "}
                      <span className="text-blue-400 font-semibold">{selectedIncident.alert_title}</span>
                    </p>
                  )}
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => handleStatusChange("in_progress")}
                      disabled={actionLoading || selectedIncident.status === "in_progress" || selectedIncident.status === "resolved" || selectedIncident.status === "closed"}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                    >
                      <Briefcase className="w-3.5 h-3.5" />
                      Prendre en charge
                    </button>
                    <button
                      onClick={() => handleStatusChange("resolved")}
                      disabled={actionLoading || selectedIncident.status === "resolved" || selectedIncident.status === "closed"}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-emerald-600 text-white hover:bg-emerald-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                    >
                      <CheckCircle className="w-3.5 h-3.5" />
                      Résoudre
                    </button>
                    <button
                      onClick={() => handleStatusChange("pending_action")}
                      disabled={actionLoading || selectedIncident.status === "pending_action" || selectedIncident.status === "resolved" || selectedIncident.status === "closed"}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-amber-600 text-white hover:bg-amber-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                    >
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Escalader
                    </button>
                  </div>
                </div>
              )}

              {/* Root Cause Card */}
              <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                  <FileText className="w-4 h-4 text-blue-500" />
                  <span>Cause Racine</span>
                </h4>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-sans">
                  {selectedIncident.root_cause ||
                    "Aucune cause racine identifiée"}
                </p>
              </div>

              {/* Lessons Learned */}
              {selectedIncident.lessons_learned && (
                <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                  <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-blue-500" />
                    <span>Leçons Apprises</span>
                  </h4>
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-sans">
                    {selectedIncident.lessons_learned}
                  </p>
                </div>
              )}

              {/* Response Actions */}
              <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                  <Briefcase className="w-4 h-4 text-blue-500" />
                  <span>Actions de Réponse</span>
                </h4>
                {selectedIncident.response_actions.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">
                    Aucune action de réponse enregistrée.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {selectedIncident.response_actions.map((action, idx) => (
                      <div
                        key={idx}
                        className="flex items-start gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50 text-xs"
                      >
                        <CheckCircle className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-slate-800 dark:text-slate-200">
                              {action.action}
                            </span>
                            <span className="text-[10px] font-mono text-slate-400">
                              {new Date(action.at).toLocaleString()}
                            </span>
                          </div>
                          <p className="text-slate-500 mt-0.5">
                            Cible: {action.target} — Par: {action.by}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Affected Assets */}
              <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-blue-500" />
                  <span>Actifs Affectés</span>
                </h4>
                {selectedIncident.affected_assets.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">
                    Aucun actif affecté identifié.
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {selectedIncident.affected_assets.map((asset, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-red-500/10 text-red-500 border border-red-500/20"
                      >
                        {asset.type}: {asset.value}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* IOC Indicators */}
              <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-blue-500" />
                  <span>Indicateurs de Compromission (IOC)</span>
                </h4>
                {selectedIncident.ioc_indicators.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">
                    Aucun IOC identifié.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {selectedIncident.ioc_indicators.map((ioc, idx) => (
                      <div
                        key={idx}
                        className="flex items-center gap-2 text-xs font-mono"
                      >
                        <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-900 text-slate-500 font-bold uppercase text-[9px]">
                          {ioc.type}
                        </span>
                        <span className="text-slate-700 dark:text-slate-300">
                          {ioc.value}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-400">
            <ShieldAlert className="w-12 h-12 text-slate-300 dark:text-slate-700 mb-2 animate-bounce" />
            <span>
              Sélectionnez un incident pour afficher ses informations détaillées
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
