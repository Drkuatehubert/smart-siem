/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from "react";
import {
  Search,
  Terminal,
  Filter,
  Download,
  ChevronDown,
  ChevronUp,
  Eye,
  Calendar,
  User as UserIcon,
  RefreshCw,
  SlidersHorizontal,
  Clock,
  Activity,
} from "lucide-react";
import api from "../../Services/api";
import type { LogEvent } from "../../types";

export default function LogsView() {
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [searching, setSearching] = useState(false);

  // Advanced search form inputs
  const [ipHostInput, setIpHostInput] = useState("");
  const [userInput, setUserInput] = useState("");
  const [logTypeInput, setLogTypeInput] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [timeRange, setTimeRange] = useState("24h");

  // Applied filters (triggered by clicking "Lancer la recherche")
  const [appliedIpHost, setAppliedIpHost] = useState("");
  const [appliedUser, setAppliedUser] = useState("");
  const [appliedLogType, setAppliedLogType] = useState("ALL");
  const [appliedSeverity, setAppliedSeverity] = useState("ALL");

  const [selectedLogId, setSelectedLogId] = useState<string | null>(null);

  useEffect(() => {
    async function loadLogs() {
      try {
        const res = await api.getLogs();
        setLogs(res);
      } catch (err) {
        console.error("Erreur chargement logs", err);
      } finally {
        setLoading(false);
      }
    }
    loadLogs();
  }, []);

  const handleSearchTrigger = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setSearching(true);
    setTimeout(() => {
      setAppliedIpHost(ipHostInput);
      setAppliedUser(userInput);
      setAppliedLogType(logTypeInput);
      setAppliedSeverity(severityFilter);
      setSearching(false);
    }, 600);
  };

  const handleResetFilters = () => {
    setIpHostInput("");
    setUserInput("");
    setLogTypeInput("ALL");
    setSeverityFilter("ALL");
    setAppliedIpHost("");
    setAppliedUser("");
    setAppliedLogType("ALL");
    setAppliedSeverity("ALL");
  };

  if (loading) {
    return (
      <div
        id="logs-loading"
        className="flex-1 flex items-center justify-center p-8"
      >
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  // Filter logs based on applied states
  const filteredLogs = logs.filter((log) => {
    const matchesSeverity =
      appliedSeverity === "ALL" || log.severity === appliedSeverity;
    const matchesCategory =
      appliedLogType === "ALL" || log.log_type === appliedLogType;

    const ipText =
      `${log.source_ip} ${log.dest_ip || ""} ${log.host}`.toLowerCase();
    const matchesIpHost =
      !appliedIpHost || ipText.includes(appliedIpHost.toLowerCase());

    const userText = `${log.username || ""}`.toLowerCase();
    const matchesUser =
      !appliedUser || userText.includes(appliedUser.toLowerCase());

    return matchesSeverity && matchesCategory && matchesIpHost && matchesUser;
  });

  const handleExport = () => {
    const dataStr =
      "data:text/json;charset=utf-8," +
      encodeURIComponent(JSON.stringify(filteredLogs, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute(
      "download",
      `SIEM_Export_Logs_${new Date().toISOString().slice(0, 10)}.json`,
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div
      id="logs-view-container"
      className="p-5 space-y-4 h-full flex flex-col overflow-hidden pb-16"
    >
      {/* 1. MOTEUR DE RECHERCHE AVANCÉ CARD */}
      <div
        id="logs-search-panel"
        className="p-5 rounded-xl border bg-white dark:bg-[#1E293B] border-slate-200 dark:border-slate-800 shadow-sm space-y-4 relative"
      >
        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              <span>Moteur de recherche avancé</span>
            </h4>
            <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">
              Interrogez des millions de logs bruts à l'aide de filtres ou de
              requêtes textuelles.
            </p>
          </div>

          <button
            onClick={() => handleSearchTrigger()}
            disabled={searching}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition-all shadow-lg hover:shadow-blue-500/20 active:scale-95 cursor-pointer disabled:opacity-70"
          >
            {searching ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Search className="w-3.5 h-3.5" />
            )}
            <span>Lancer la recherche</span>
          </button>
        </div>

        <form
          onSubmit={handleSearchTrigger}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3.5"
        >
          {/* IP / Host field */}
          <div className="space-y-1">
            <label className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 flex items-center gap-1.5">
              <Terminal className="w-3 h-3 text-slate-400" />
              <span>Adresse IP / Host</span>
            </label>
            <input
              type="text"
              placeholder="ex: 192.168.1.10"
              value={ipHostInput}
              onChange={(e) => setIpHostInput(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all font-mono"
            />
          </div>

          {/* User field */}
          <div className="space-y-1">
            <label className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 flex items-center gap-1.5">
              <UserIcon className="w-3 h-3 text-slate-400" />
              <span>Utilisateur</span>
            </label>
            <input
              type="text"
              placeholder="ex: admin_root"
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all font-mono"
            />
          </div>

          {/* Log Type dropdown */}
          <div className="space-y-1">
            <label className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 flex items-center gap-1.5">
              <Filter className="w-3 h-3 text-slate-400" />
              <span>Type de log</span>
            </label>
            <select
              value={logTypeInput}
              onChange={(e) => setLogTypeInput(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all font-mono cursor-pointer appearance-none"
            >
              <option value="ALL">Tous les logs</option>
              <option value="auth">Authentification</option>
              <option value="network">Réseau</option>
              <option value="system">Système</option>
              <option value="application">Application</option>
              <option value="audit">Audit</option>
            </select>
          </div>

          {/* Plage Horaire dropdown */}
          <div className="space-y-1">
            <label className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 flex items-center gap-1.5">
              <Calendar className="w-3 h-3 text-slate-400" />
              <span>Plage horaire</span>
            </label>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all font-mono cursor-pointer"
            >
              <option value="24h">Dernières 24 heures</option>
              <option value="7d">Derniers 7 jours</option>
              <option value="30d">Derniers 30 jours</option>
              <option value="custom">Plage personnalisée</option>
            </select>
          </div>

          {/* Criticité toggles */}
          <div className="space-y-1">
            <label className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 flex items-center gap-1.5">
              <Clock className="w-3 h-3 text-slate-400" />
              <span>Criticité</span>
            </label>
            <div className="grid grid-cols-4 gap-1">
              {[
                { id: "info", label: "Info" },
                { id: "warning", label: "Avert." },
                { id: "high", label: "Haute" },
                { id: "critical", label: "Crit." },
              ].map((c) => (
                <button
                  type="button"
                  key={c.id}
                  onClick={() =>
                    setSeverityFilter(severityFilter === c.id ? "ALL" : c.id)
                  }
                  className={`py-2 rounded-lg text-[10px] font-bold uppercase border transition-all cursor-pointer ${
                    severityFilter === c.id
                      ? "bg-blue-500 text-white border-blue-500 shadow-md shadow-blue-500/10"
                      : "bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-900/60"
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </div>
        </form>

        {searching && (
          <div className="absolute inset-x-0 bottom-0 h-1 bg-slate-100 dark:bg-slate-900 overflow-hidden rounded-b-xl">
            <div className="h-full bg-blue-500 animate-[loading-bar_1s_infinite]"></div>
          </div>
        )}
      </div>

      {/* 2. TIMELINE DES ÉVÉNEMENTS CARD */}
      <div
        id="logs-timeline-panel"
        className="p-4 rounded-xl border bg-white dark:bg-[#1E293B] border-slate-200 dark:border-slate-800 shadow-sm space-y-3.5"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-slate-500 dark:text-slate-400" />
            <h4 className="font-bold text-xs uppercase tracking-wider text-slate-400 dark:text-slate-500 font-mono">
              TIMELINE DES ÉVÉNEMENTS
            </h4>
          </div>

          {/* Legends */}
          <div className="flex items-center gap-4 text-[10px] font-mono font-bold">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-red-500"></span>
              <span className="text-slate-500">Critique</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-orange-500"></span>
              <span className="text-slate-500">Avertissement</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-blue-500"></span>
              <span className="text-slate-500">Info</span>
            </div>
          </div>
        </div>

        {/* Timeline Line & Nodes, Matching Mockup Perfectly */}
        <div className="relative pt-6 pb-2 px-10">
          <div className="absolute top-1/2 left-10 right-10 h-0.5 bg-slate-200 dark:bg-slate-850 -translate-y-1/2"></div>

          <div className="relative flex justify-between items-center z-10">
            {/* Node 00:00 */}
            <div className="flex flex-col items-center">
              <button
                onClick={() => {
                  setSeverityFilter("info");
                  handleSearchTrigger();
                }}
                className="w-3.5 h-3.5 rounded-full bg-blue-500 border-2 border-white dark:border-slate-800 shadow hover:scale-125 transition-all cursor-pointer"
                title="Sévérité info"
              ></button>
              <span className="text-[10px] font-mono text-slate-400 mt-2">
                00:00
              </span>
            </div>

            {/* Node 07:00 (Pulsing critical spike from the screenshot) */}
            <div className="flex flex-col items-center -translate-y-2">
              <button
                onClick={() => {
                  setSeverityFilter("high");
                  handleSearchTrigger();
                }}
                className="px-3 py-1 bg-red-600 hover:bg-red-500 text-white font-mono text-[9px] font-extrabold rounded-full shadow-lg shadow-red-500/20 border-2 border-white dark:border-slate-800 animate-bounce flex items-center gap-1.5 cursor-pointer"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-white animate-ping"></span>
                <span>1,284 ALERTES</span>
              </button>
              <span className="text-[10px] font-mono text-slate-400 mt-2">
                07:00
              </span>
            </div>

            {/* Node 15:00 */}
            <div className="flex flex-col items-center">
              <button
                onClick={() => {
                  setSeverityFilter("warning");
                  handleSearchTrigger();
                }}
                className="w-3.5 h-3.5 rounded-full bg-orange-500 border-2 border-white dark:border-slate-800 shadow hover:scale-125 transition-all cursor-pointer"
                title="Sévérité warning"
              ></button>
              <span className="text-[10px] font-mono text-slate-400 mt-2">
                15:00
              </span>
            </div>

            {/* Node 23:59 */}
            <div className="flex flex-col items-center">
              <button
                onClick={() => {
                  setSeverityFilter("ALL");
                  handleSearchTrigger();
                }}
                className="w-3.5 h-3.5 rounded-full bg-blue-500 border-2 border-white dark:border-slate-800 shadow hover:scale-125 transition-all cursor-pointer"
                title="Tous les événements"
              ></button>
              <span className="text-[10px] font-mono text-slate-400 mt-2">
                23:59
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. LOGS RESULTS PANEL */}
      <div
        id="logs-results-panel"
        className="flex-1 border bg-white dark:bg-[#1E293B] border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden flex flex-col shadow-sm"
      >
        {/* Table Header Controls */}
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/10 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <h4 className="font-bold text-sm text-slate-800 dark:text-slate-100">
              Événements Détectés
            </h4>
            <span className="px-2.5 py-0.5 rounded-full bg-blue-50 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400 font-bold font-mono text-[10px] border border-blue-100 dark:border-blue-900/30">
              {filteredLogs.length} Résultats
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleExport}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold font-mono text-xs transition-all active:scale-95 cursor-pointer"
              title="Exporter les logs filtrés au format JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Exporter</span>
            </button>
            <button
              onClick={handleResetFilters}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold font-mono text-xs transition-all active:scale-95 cursor-pointer"
              title="Réinitialiser tous les filtres actifs"
            >
              <SlidersHorizontal className="w-3.5 h-3.5" />
              <span>Réinitialiser</span>
            </button>
          </div>
        </div>

        {/* Scrollable Logs Table */}
        <div className="flex-1 overflow-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/30 text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 select-none">
                <th className="py-2.5 px-6 w-12"></th>
                <th className="py-2.5 px-4 w-44">Horodatage</th>
                <th className="py-2.5 px-4 w-28 text-center">Type</th>
                <th className="py-2.5 px-4">Message</th>
                <th className="py-2.5 px-4 w-32">Source IP</th>
                <th className="py-2.5 px-4 w-28">Utilisateur</th>
                <th className="py-2.5 px-4 w-24 text-center">Criticité</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono text-xs text-slate-700 dark:text-slate-300">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <Terminal className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-3 animate-pulse" />
                    <span>
                      Aucun log brut ne correspond aux filtres saisis.
                    </span>
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => {
                  const isExpanded = selectedLogId === log.raw_log_id;

                  // Severity tags colors based on standard levels
                  const severityConfig =
                    log.severity === "critical"
                      ? {
                          text: "Critique",
                          style: "text-red-500 bg-red-500/10 border-red-500/20",
                        }
                      : log.severity === "high"
                        ? {
                            text: "Haute",
                            style:
                              "text-orange-500 bg-orange-500/10 border-orange-500/20",
                          }
                        : log.severity === "warning"
                          ? {
                              text: "Avert.",
                              style:
                                "text-amber-500 bg-amber-500/10 border-amber-500/20",
                            }
                          : {
                              text: "Info",
                              style:
                                "text-blue-500 bg-blue-500/10 border-blue-500/20",
                            };

                  // Custom type tags based on log_type
                  const logTypeBadge = () => {
                    if (log.log_type === "auth") {
                      return (
                        <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-orange-600 dark:text-orange-400 bg-orange-100/50 dark:bg-orange-950/30 border border-orange-200 dark:border-orange-900/20">
                          SECURITY
                        </span>
                      );
                    } else if (log.log_type === "network") {
                      return (
                        <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-emerald-600 dark:text-emerald-400 bg-emerald-100/50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/20">
                          FIREWALL
                        </span>
                      );
                    } else if (log.log_type === "system") {
                      return (
                        <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-blue-600 dark:text-blue-400 bg-blue-100/50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900/20">
                          SYSTEM
                        </span>
                      );
                    } else if (log.log_type === "application") {
                      return (
                        <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-red-600 dark:text-red-400 bg-red-100/50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/20">
                          APP
                        </span>
                      );
                    } else {
                      return (
                        <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-purple-600 dark:text-purple-400 bg-purple-100/50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-900/20">
                          AUDIT
                        </span>
                      );
                    }
                  };

                  return (
                    <React.Fragment key={log.raw_log_id}>
                      <tr
                        onClick={() =>
                          setSelectedLogId(isExpanded ? null : log.raw_log_id)
                        }
                        className={`hover:bg-slate-50 dark:hover:bg-slate-800/20 transition-all cursor-pointer ${
                          isExpanded ? "bg-slate-50 dark:bg-slate-800/10" : ""
                        }`}
                      >
                        <td className="py-2.5 px-6 text-center text-slate-400 shrink-0 select-none">
                          {isExpanded ? (
                            <ChevronUp className="w-3.5 h-3.5 text-blue-500" />
                          ) : (
                            <ChevronDown className="w-3.5 h-3.5" />
                          )}
                        </td>
                        <td className="py-2.5 px-4 text-slate-400 text-[11px] font-medium">
                          {new Date(log["@timestamp"]).toLocaleString()}
                        </td>
                        <td className="py-2.5 px-4 text-center font-bold">
                          {logTypeBadge()}
                        </td>
                        <td className="py-2.5 px-4 truncate max-w-sm text-slate-800 dark:text-slate-200 font-sans font-medium text-xs">
                          {log.raw_message}
                        </td>
                        <td className="py-2.5 px-4 font-bold text-slate-600 dark:text-slate-450">
                          {log.source_ip}
                        </td>
                        <td className="py-2.5 px-4 font-semibold text-slate-500 dark:text-slate-400">
                          {log.username || "system_root"}
                        </td>
                        <td className="py-2.5 px-4 text-center">
                          <span
                            className={`px-2.5 py-0.5 rounded-full text-[9px] font-bold border ${severityConfig.style}`}
                          >
                            {severityConfig.text}
                          </span>
                        </td>
                      </tr>

                      {/* Expandable JSON Detail View */}
                      {isExpanded && (
                        <tr>
                          <td
                            colSpan={7}
                            className="p-0 bg-slate-50/50 dark:bg-slate-900/10"
                          >
                            <div className="px-12 py-5 border-t border-b border-slate-100 dark:border-slate-800/60 text-slate-850 dark:text-slate-200 font-mono text-[11px] leading-relaxed">
                              <div className="flex items-center justify-between mb-3 text-[10px] uppercase text-slate-400 dark:text-slate-500 font-bold tracking-wider">
                                <span>
                                  Informations détaillées du document de log
                                  (Elasticsearch Entry)
                                </span>
                                <span className="flex items-center gap-1.5">
                                  <Eye className="w-3.5 h-3.5" />{" "}
                                  ELASTIC_INDEX_READY
                                </span>
                              </div>
                              <pre className="bg-white dark:bg-slate-950 p-4 rounded-xl border border-slate-200 dark:border-slate-800 overflow-x-auto text-slate-800 dark:text-slate-300 max-h-60 shadow-inner">
                                {JSON.stringify(log, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
