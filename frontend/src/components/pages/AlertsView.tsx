import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  Clock,
  CheckCircle,
  AlertTriangle,
  Server,
  Activity,
  RefreshCw,
  Ban,
  XCircle,
  Zap,
  X,
} from "lucide-react";
import api from "../../Services/api";
import type { Alert, UserRole } from "../../types";
import { RBAC_POLICIES, type ModuleID } from "../../utils/rbac";

interface AlertsViewProps {
  activeRole: UserRole;
  setActiveModule?: (m: ModuleID) => void;
}

const LEVEL_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  warning:  "bg-amber-500",
  info:     "bg-blue-500",
};

const LEVEL_BADGE: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/20",
  high:     "text-orange-500 bg-orange-500/10 border-orange-500/20",
  warning:  "text-amber-500 bg-amber-500/10 border-amber-500/20",
  info:     "text-blue-500 bg-blue-500/10 border-blue-500/20",
};

const STATUS_BADGE: Record<string, string> = {
  open:          "text-rose-500 border-rose-500/20 bg-rose-500/5",
  investigating: "text-amber-500 border-amber-500/20 bg-amber-500/5",
  confirmed:     "text-purple-500 border-purple-500/20 bg-purple-500/5",
  escalated:     "text-red-600 border-red-600/20 bg-red-600/5",
  false_positive:"text-slate-400 border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/10",
};

const STATUS_LABEL: Record<string, string> = {
  open:          "Ouvert",
  investigating: "En cours",
  confirmed:     "Confirmé",
  escalated:     "Escaladé",
  false_positive:"Faux positif",
  closed:        "Clos",
};

export default function AlertsView({ activeRole, setActiveModule }: AlertsViewProps) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const [levelFilter, setLevelFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [soarLoading, setSoarLoading] = useState(false);
  const [toast, setToast] = useState<{
    msg: string;
    type: "success" | "error";
    link?: { label: string; module: ModuleID };
  } | null>(null);

  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [modalTitre, setModalTitre] = useState("");
  const [modalPriorite, setModalPriorite] = useState("P3");
  const [modalSubmitting, setModalSubmitting] = useState(false);

  const canEdit = RBAC_POLICIES[activeRole].canEditIncidents;

  const showToast = (
    msg: string,
    type: "success" | "error" = "success",
    link?: { label: string; module: ModuleID },
  ) => {
    setToast({ msg, type, link });
    setTimeout(() => setToast(null), 5000);
  };

  async function load(showSpinner = false) {
    if (showSpinner) setRefreshing(true);
    try {
      const res = await api.getAlerts();
      setAlerts(res);
      if (res.length > 0 && !selectedId) setSelectedId(res[0].id);
    } catch (err) {
      console.error("Erreur chargement alertes", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => { load(); }, []);

  const handleAcknowledge = async () => {
    if (!selectedId) return;
    try {
      await api.acknowledgeAlert(selectedId, "analyst", activeRole);
      // Mise à jour partielle : on ne touche qu'au statut, le reste est conservé
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === selectedId ? { ...a, status: "investigating" as Alert["status"] } : a
        )
      );
    } catch (err) {
      console.error("Erreur acquittement", err);
    }
  };

  const handleTriggerSoar = async () => {
    if (!selectedId) return;
    setSoarLoading(true);
    try {
      await api.triggerSoar(selectedId);
      showToast("IP bloquée sur pfSense");
    } catch (err) {
      console.error("Erreur SOAR trigger", err);
      showToast("Erreur lors du déclenchement SOAR", "error");
    } finally {
      setSoarLoading(false);
    }
  };

  const handleMarkFalsePositive = async () => {
    if (!selectedId) return;
    try {
      await api.updateAlertStatus(selectedId, "false_positive", "analyst", activeRole);
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === selectedId ? { ...a, status: "false_positive" as Alert["status"] } : a
        )
      );
      showToast("Alerte marquée comme faux positif");
    } catch (err) {
      console.error("Erreur faux positif", err);
      showToast("Erreur lors de la mise à jour", "error");
    }
  };

  const PRIORITE_MAP: Record<string, string> = {
    critical: "P1", high: "P2", warning: "P3", info: "P4",
    CRITICAL: "P1", HIGH: "P2", WARNING: "P3", INFO: "P4",
  };

  const handleOpenModal = () => {
    if (!selected) return;
    setModalTitre(selected.title || "");
    setModalPriorite(PRIORITE_MAP[selected.level] ?? "P3");
    setShowModal(true);
  };

  const handleSubmitIncident = async () => {
    if (!selected) return;
    setModalSubmitting(true);
    try {
      await api.createIncident(
        selected.id,
        modalTitre || selected.title || "Incident sans titre",
        modalPriorite as never,
        "analyst",
        activeRole,
      );
      setShowModal(false);
      showToast(
        "Incident créé avec succès.",
        "success",
        { label: "Voir les incidents →", module: "incidents" },
      );
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      const msg = status === 409 || status === 400
        ? "Un incident existe déjà pour cette alerte"
        : "Erreur lors de la création de l'incident";
      showToast(msg, "error");
    } finally {
      setModalSubmitting(false);
    }
  };

  const handleStatusChange = async (newStatus: Alert["status"]) => {
    if (!selectedId) return;
    try {
      await api.updateAlertStatus(selectedId, newStatus, "analyst", activeRole);
      // Mise à jour partielle : on ne touche qu'au statut, le reste est conservé
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === selectedId ? { ...a, status: newStatus } : a
        )
      );
    } catch (err) {
      console.error("Erreur changement statut", err);
    }
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const filtered = alerts.filter((a) => {
    const lvl = levelFilter === "ALL" || a.level === levelFilter;
    const st  = statusFilter === "ALL" || a.status === statusFilter;
    return lvl && st;
  });

  const selected = alerts.find((a) => a.id === selectedId) ?? null;

  return (
    <div id="alerts-view" className="h-full flex overflow-hidden relative">
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
          {toast.link && setActiveModule && (
            <button
              onClick={() => { setActiveModule(toast.link!.module); setToast(null); }}
              className="underline font-bold hover:opacity-80 cursor-pointer"
            >
              {toast.link.label}
            </button>
          )}
          <button onClick={() => setToast(null)} className="ml-1 opacity-60 hover:opacity-100">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
      {/* LEFT PANEL */}
      <div className="w-80 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0b0f19] flex flex-col shrink-0 h-full">
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <h4 className="font-bold text-xs uppercase text-slate-400 dark:text-slate-500 font-mono tracking-wider">
              FILTRER LES ALERTES
            </h4>
            <button
              onClick={() => load(true)}
              disabled={refreshing}
              className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 disabled:opacity-50"
              title="Actualiser"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-slate-400 font-bold font-mono">STATUT</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full mt-1 px-2.5 py-1.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
              >
                <option value="ALL">Tous</option>
                <option value="open">Ouvert</option>
                <option value="investigating">En cours</option>
                <option value="confirmed">Confirmé</option>
                <option value="escalated">Escaladé</option>
                <option value="false_positive">Faux positif</option>
                <option value="closed">Clos</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] text-slate-400 font-bold font-mono">SÉVÉRITÉ</label>
              <select
                value={levelFilter}
                onChange={(e) => setLevelFilter(e.target.value)}
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

          <p className="text-[10px] text-slate-400 font-mono">
            {filtered.length} alerte{filtered.length !== 1 ? "s" : ""}
          </p>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/60">
          {filtered.length === 0 ? (
            <div className="p-6 text-center text-slate-400 dark:text-slate-500 font-medium text-xs">
              <ShieldAlert className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2" />
              <span>Aucune alerte détectée</span>
            </div>
          ) : (
            filtered.map((alert) => {
              const isSelected = alert.id === selectedId;
              return (
                <button
                  key={alert.id}
                  onClick={() => setSelectedId(alert.id)}
                  className={`w-full text-left p-4 transition-all flex flex-col gap-2 relative border-l-4 ${
                    isSelected
                      ? "bg-blue-50/40 dark:bg-blue-950/10 border-l-blue-600"
                      : "border-transparent hover:bg-slate-50/50 dark:hover:bg-slate-900/10"
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <div className="flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${LEVEL_DOT[alert.level] ?? "bg-slate-400"}`} />
                      <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                        {alert.level}
                      </span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${STATUS_BADGE[alert.status] ?? ""}`}>
                      {STATUS_LABEL[alert.status] ?? alert.status}
                    </span>
                  </div>

                  <h5 className="font-bold text-xs text-slate-800 dark:text-slate-200 line-clamp-2 leading-tight">
                    {alert.title}
                  </h5>

                  <span className="text-[10px] text-slate-400 font-mono">
                    {alert.triggered_at
                      ? new Date(alert.triggered_at).toLocaleString("fr-FR")
                      : "—"}
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>

      {/* RIGHT PANEL */}
      <div className="flex-1 bg-slate-50 dark:bg-[#0F172A] flex flex-col h-full overflow-hidden">
        {selected ? (
          <div className="flex-1 flex flex-col h-full overflow-hidden">
            {/* Header */}
            <div className="p-6 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-[#1E293B] shrink-0 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span className={`px-2.5 py-0.5 rounded-full font-bold text-[10px] uppercase border font-mono ${LEVEL_BADGE[selected.level] ?? ""}`}>
                    {selected.level}
                  </span>
                  <span className="text-xs font-mono font-bold text-slate-400">
                    Score: {selected.confidence_score}%
                  </span>
                </div>

                {canEdit ? (
                  <div className="flex items-center gap-3">
                    <button
                      onClick={handleAcknowledge}
                      disabled={selected.status !== "open"}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                    >
                      <CheckCircle className="w-3.5 h-3.5" />
                      Acquitter
                    </button>
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-400" />
                      <select
                        value={selected.status}
                        onChange={(e) => handleStatusChange(e.target.value as Alert["status"])}
                        className="px-2.5 py-1.5 rounded-lg border text-xs bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none"
                      >
                        <option value="open">Ouvert</option>
                        <option value="investigating">En cours</option>
                        <option value="confirmed">Confirmé</option>
                        <option value="escalated">Escaladé</option>
                    <option value="false_positive">Faux positif</option>
                    <option value="closed">Clos</option>
                      </select>
                    </div>
                  </div>
                ) : (
                  <span className={`px-2.5 py-0.5 rounded text-[9px] font-mono font-bold border ${STATUS_BADGE[selected.status] ?? ""}`}>
                    {STATUS_LABEL[selected.status] ?? selected.status}
                  </span>
                )}
              </div>

              <h3 className="text-base font-bold text-slate-900 dark:text-slate-50 tracking-tight leading-snug">
                {selected.title || <span className="italic text-slate-400">Titre non disponible</span>}
              </h3>

              <div className="flex flex-wrap items-center gap-4 text-[10px] text-slate-400 font-mono">
                <span>Détectée le {selected.triggered_at ? new Date(selected.triggered_at).toLocaleString("fr-FR") : "—"}</span>
                {selected.rule_name && (
                  <span className="text-slate-500">Règle : <span className="text-blue-400 font-bold">{selected.rule_name}</span></span>
                )}
                <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${STATUS_BADGE[selected.status] ?? ""}`}>
                  {STATUS_LABEL[selected.status] ?? selected.status}
                </span>
              </div>
            </div>

            {/* Detail body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-5">
              {/* Actions manuelles */}
              {canEdit && (
                <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                  <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                    <Zap className="w-4 h-4 text-amber-500" />
                    Actions manuelles
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {/* Bloquer l'IP */}
                    {selected.source_ips.length > 0 && (
                      <button
                        onClick={handleTriggerSoar}
                        disabled={soarLoading}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-red-600 text-white hover:bg-red-700 disabled:opacity-50 disabled:cursor-wait transition-all"
                      >
                        {soarLoading
                          ? <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                          : <Ban className="w-3.5 h-3.5" />}
                        Bloquer l&apos;IP
                      </button>
                    )}
                    {/* Marquer faux positif */}
                    <button
                      onClick={handleMarkFalsePositive}
                      disabled={selected.status === "false_positive"}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all border border-slate-200 dark:border-slate-700"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      Faux positif
                    </button>
                    {/* Créer un incident */}
                    <button
                      onClick={handleOpenModal}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-purple-600 text-white hover:bg-purple-700 transition-all"
                    >
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Créer un incident
                    </button>
                  </div>
                </div>
              )}
              {/* IPs sources */}
              <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                  <Activity className="w-4 h-4 text-blue-500" />
                  IPs Sources
                </h4>
                {selected.source_ips.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">Aucune IP source</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {selected.source_ips.map((ip, i) => (
                      <span key={i} className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-orange-500/10 text-orange-500 border border-orange-500/20">
                        {ip}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Hosts affectés */}
              <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                  <Server className="w-4 h-4 text-blue-500" />
                  Hôtes Affectés
                </h4>
                {selected.affected_hosts.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">Aucun hôte affecté</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {selected.affected_hosts.map((h, i) => (
                      <span key={i} className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-red-500/10 text-red-500 border border-red-500/20">
                        {h}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* MITRE */}
              {selected.mitre_tactic && (
                <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                  <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-blue-500" />
                    Tactique MITRE ATT&CK
                  </h4>
                  <span className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-purple-500/10 text-purple-500 border border-purple-500/20">
                    {selected.mitre_tactic}
                  </span>
                </div>
              )}

              {/* Notes */}
              {selected.notes && (
                <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                  <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-blue-500" />
                    Notes
                  </h4>
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                    {selected.notes}
                  </p>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-400">
            <ShieldAlert className="w-12 h-12 text-slate-300 dark:text-slate-700 mb-2 animate-bounce" />
            <span>Sélectionnez une alerte pour afficher ses détails</span>
          </div>
        )}
      </div>

      {/* Modal : Créer un incident */}
      {showModal && (
        <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#1E293B] rounded-xl border border-slate-200 dark:border-slate-700 shadow-2xl w-full max-w-md p-6 space-y-5 mx-4">
            <div className="flex items-center justify-between">
              <h3 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-purple-500" />
                Créer un incident
              </h3>
              <button
                onClick={() => setShowModal(false)}
                className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-[10px] font-bold font-mono text-slate-400 uppercase">
                  Titre de l&apos;incident
                </label>
                <input
                  type="text"
                  value={modalTitre}
                  onChange={(e) => setModalTitre(e.target.value)}
                  className="w-full mt-1 px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-purple-500/40"
                />
              </div>
              <div>
                <label className="text-[10px] font-bold font-mono text-slate-400 uppercase">
                  Priorité
                </label>
                <select
                  value={modalPriorite}
                  onChange={(e) => setModalPriorite(e.target.value)}
                  className="w-full mt-1 px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none"
                >
                  <option value="P1">P1 — Critique</option>
                  <option value="P2">P2 — Haute</option>
                  <option value="P3">P3 — Moyenne</option>
                  <option value="P4">P4 — Basse</option>
                </select>
              </div>
              <div className="text-[10px] text-slate-400 bg-slate-50 dark:bg-slate-900/50 rounded-lg p-2.5 border border-slate-200 dark:border-slate-800">
                Alerte source :{" "}
                <span className="font-semibold text-slate-600 dark:text-slate-300">
                  {selected?.title}
                </span>
              </div>
            </div>

            <div className="flex gap-2 pt-1">
              <button
                onClick={() => setShowModal(false)}
                className="flex-1 py-2 rounded-lg text-xs font-semibold text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-all"
              >
                Annuler
              </button>
              <button
                onClick={handleSubmitIncident}
                disabled={!modalTitre.trim() || modalSubmitting}
                className="flex-1 py-2 rounded-lg text-xs font-bold bg-purple-600 text-white hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-1.5"
              >
                {modalSubmitting && (
                  <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                )}
                Confirmer la création
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
