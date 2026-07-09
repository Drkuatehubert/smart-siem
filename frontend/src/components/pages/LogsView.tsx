/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
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
  BarChart2,
  FileText,
  Flag,
} from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import api from "../../Services/api";
import type { LogEvent } from "../../types";

export default function LogsView() {
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searching, setSearching] = useState(false);
  const [eventActions, setEventActions] = useState<string[]>([]);

  // Flagged log IDs — persisted in localStorage
  const [flaggedIds, setFlaggedIds] = useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem("siem_flagged_logs");
      return new Set(stored ? (JSON.parse(stored) as string[]) : []);
    } catch {
      return new Set();
    }
  });

  // Search form inputs
  const [ipHostInput, setIpHostInput] = useState("");
  const [userInput, setUserInput] = useState("");
  const [eventActionInput, setEventActionInput] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [timeRange, setTimeRange] = useState("24h");

  // Applied filters (committed when "Lancer la recherche" is clicked)
  const [appliedIpHost, setAppliedIpHost] = useState("");
  const [appliedUser, setAppliedUser] = useState("");
  const [appliedEventAction, setAppliedEventAction] = useState("ALL");
  const [appliedSeverity, setAppliedSeverity] = useState("ALL");

  const [selectedLogId, setSelectedLogId] = useState<string | null>(null);

  // Density data — grouped by hour from loaded logs
  const densityData = useMemo(() => {
    const byHour: Record<string, { login_failed: number; login_success: number; autres: number }> = {};
    logs.forEach((log) => {
      const ts = log["@timestamp"];
      if (!ts) return;
      const d = new Date(ts);
      if (isNaN(d.getTime())) return;
      const hour = d.getHours().toString().padStart(2, "0") + ":00";
      if (!byHour[hour]) byHour[hour] = { login_failed: 0, login_success: 0, autres: 0 };
      if (log.event_action === "login_failed") byHour[hour].login_failed++;
      else if (log.event_action === "login_success") byHour[hour].login_success++;
      else byHour[hour].autres++;
    });
    return Object.entries(byHour)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([hour, counts]) => ({ hour, ...counts }));
  }, [logs]);

  // ── Data loading ───────────────────────────────────────────────────────────

  const loadLogs = useCallback(async () => {
    setRefreshing(true);
    try {
      const res = await api.getLogsPage(200);
      setLogs(res.items);
      setTotalLogs(res.total);
    } catch (err) {
      console.error("Erreur chargement logs", err);
    } finally {
      setRefreshing(false);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  // Load dynamic event_action values from ES
  useEffect(() => {
    api.getEventActions().then(setEventActions).catch(() => setEventActions([]));
  }, []);

  // ── Handlers ───────────────────────────────────────────────────────────────

  const handleSearchTrigger = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setSearching(true);
    setTimeout(() => {
      setAppliedIpHost(ipHostInput);
      setAppliedUser(userInput);
      setAppliedEventAction(eventActionInput);
      setAppliedSeverity(severityFilter);
      setSearching(false);
    }, 400);
  };

  const handleResetFilters = () => {
    setIpHostInput("");
    setUserInput("");
    setEventActionInput("ALL");
    setSeverityFilter("ALL");
    setTimeRange("24h");
    setAppliedIpHost("");
    setAppliedUser("");
    setAppliedEventAction("ALL");
    setAppliedSeverity("ALL");
    loadLogs();
  };

  const handleRefresh = () => {
    loadLogs();
  };

  const toggleFlag = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setFlaggedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      try {
        localStorage.setItem("siem_flagged_logs", JSON.stringify([...next]));
      } catch {}
      return next;
    });
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

  // ── Filtrage ──────────────────────────────────────────────────────────────

  const filteredLogs = logs.filter((log) => {
    const matchesSeverity =
      appliedSeverity === "ALL" || log.severity === appliedSeverity;
    const matchesEventAction =
      appliedEventAction === "ALL" || log.event_action === appliedEventAction;

    const ipText =
      `${log.source_ip} ${log.dest_ip || ""} ${log.host}`.toLowerCase();
    const matchesIpHost =
      !appliedIpHost || ipText.includes(appliedIpHost.toLowerCase());

    const userText = `${log.username || ""}`.toLowerCase();
    const matchesUser =
      !appliedUser || userText.includes(appliedUser.toLowerCase());

    return matchesSeverity && matchesEventAction && matchesIpHost && matchesUser;
  });

  // ── Exports ────────────────────────────────────────────────────────────────

  const handleExportCSV = () => {
    const BOM = '﻿';
    const header = '"Horodatage","Type","Message","Source IP","Utilisateur","Criticité"\n';
    const rows = filteredLogs.map((l) =>
      [
        l['@timestamp'] || '',
        l.event_action || '',
        (l.raw_message || '').replace(/"/g, '""'),
        l.source_ip || '',
        l.username || '',
        l.severity || '',
      ]
        .map((v) => `"${v}"`)
        .join(',')
    );
    const csv = BOM + header + rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `smart-siem-investigation-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportPDF = () => {
    const printWindow = window.open('', '_blank', 'width=960,height=700');
    if (!printWindow) return;

    const dateStr = new Date().toLocaleString('fr-FR');
    const rowsHtml = filteredLogs
      .map(
        (log) => `
        <tr>
          <td>${new Date(log['@timestamp']).toLocaleString('fr-FR')}</td>
          <td>${log.event_action || '—'}</td>
          <td class="msg">${(log.raw_message || '—').substring(0, 90)}</td>
          <td>${log.source_ip || '—'}</td>
          <td>${log.username || '—'}</td>
          <td class="sev ${log.severity}">${log.severity || '—'}</td>
        </tr>`
      )
      .join('');

    printWindow.document.write(`<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"/>
  <title>Smart SIEM — Investigation ${new Date().toISOString().slice(0, 10)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Courier New', monospace; font-size: 10px; color: #1a1a2e; padding: 20px; }
    header { background: #1e3a5f; color: white; padding: 14px 20px; border-radius: 6px; margin-bottom: 14px; }
    header h1 { font-size: 16px; letter-spacing: 1px; }
    header p  { font-size: 9px; opacity: .75; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th { background: #1e3a5f; color: white; padding: 6px 8px; text-align: left; font-size: 9px; }
    td { padding: 4px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    tr:nth-child(even) td { background: #f8fafc; }
    .msg { max-width: 280px; word-break: break-word; }
    .sev.critical { color: #dc2626; font-weight: bold; }
    .sev.high     { color: #ea580c; font-weight: bold; }
    .sev.warning  { color: #d97706; font-weight: bold; }
    .sev.info     { color: #2563eb; }
    footer { margin-top: 16px; font-size: 8px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 8px; }
    @media print { body { padding: 10px; } header { -webkit-print-color-adjust: exact; print-color-adjust: exact; } th { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
  </style>
</head>
<body>
  <header>
    <h1>SMART SIEM — Rapport d'Investigation</h1>
    <p>Généré le : ${dateStr} &nbsp;|&nbsp; ${filteredLogs.length} événements affichés sur ${totalLogs} total ES</p>
  </header>
  <table>
    <thead>
      <tr>
        <th>Horodatage</th><th>Type</th><th>Message</th>
        <th>Source IP</th><th>Utilisateur</th><th>Criticité</th>
      </tr>
    </thead>
    <tbody>${rowsHtml}</tbody>
  </table>
  <footer>Confidentiel — Usage interne uniquement &nbsp;|&nbsp; Smart SIEM v1.0 &nbsp;|&nbsp; ISO 27001 / RGPD</footer>
</body>
</html>`);

    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
      printWindow.close();
    }, 300);
  };

  // ── Render ─────────────────────────────────────────────────────────────────

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
            disabled={searching || refreshing}
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

          {/* Type d'événement — dynamic dropdown from ES */}
          <div className="space-y-1">
            <label className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 flex items-center gap-1.5">
              <Filter className="w-3 h-3 text-slate-400" />
              <span>Type d'événement</span>
            </label>
            <select
              value={eventActionInput}
              onChange={(e) => setEventActionInput(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all font-mono cursor-pointer appearance-none"
            >
              <option value="ALL">Tous les événements</option>
              {eventActions.map((action) => (
                <option key={action} value={action}>{action}</option>
              ))}
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

      {/* 2. GRAPHE DE DENSITÉ */}
      {logs.length > 0 && (
        <div
          id="logs-density-panel"
          className="px-5 pt-4 pb-3 rounded-xl border bg-white dark:bg-[#1E293B] border-slate-200 dark:border-slate-800 shadow-sm space-y-3"
        >
          <div className="flex items-center justify-between">
            <div>
              <h4 className="font-bold text-sm text-slate-800 dark:text-slate-100 flex items-center gap-1.5">
                <BarChart2 className="w-4 h-4 text-blue-500" />
                Densité des événements (dernières 24h)
              </h4>
              <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                Pics = moments d'activité intense
              </p>
            </div>
            <div className="flex items-center gap-4 text-[10px] font-mono text-slate-500 dark:text-slate-400">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ background: "#E24B4A" }}></span>
                Échecs login
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ background: "#639922" }}></span>
                Connexions
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ background: "#888780" }}></span>
                Autres
              </span>
            </div>
          </div>

          <ResponsiveContainer width="100%" height={120}>
            <AreaChart data={densityData} margin={{ top: 4, right: 4, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.2)" />
              <XAxis dataKey="hour" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10 }} width={30} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{
                  fontSize: 11,
                  borderRadius: 8,
                  border: "1px solid #e2e8f0",
                  backgroundColor: "rgba(255,255,255,0.95)",
                }}
              />
              <Area
                type="monotone"
                dataKey="login_failed"
                stackId="1"
                stroke="#E24B4A"
                fill="#FCEBEB"
                name="Échecs login"
                dot={(dotProps: any) => {
                  const { cx, cy, payload, key } = dotProps;
                  if ((payload?.login_failed ?? 0) > 5) {
                    return (
                      <circle
                        key={key}
                        cx={cx}
                        cy={cy}
                        r={5}
                        fill="#E24B4A"
                        stroke="#fff"
                        strokeWidth={2}
                      />
                    );
                  }
                  return <React.Fragment key={key} />;
                }}
              />
              <Area
                type="monotone"
                dataKey="login_success"
                stackId="1"
                stroke="#639922"
                fill="#EAF3DE"
                name="Connexions"
                dot={false}
              />
              <Area
                type="monotone"
                dataKey="autres"
                stackId="1"
                stroke="#888780"
                fill="#F1EFE8"
                name="Autres"
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

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
              {filteredLogs.length} / {totalLogs > 0 ? totalLogs.toLocaleString("fr-FR") : logs.length} résultats
            </span>
          </div>

          <div className="flex items-center gap-2">
            {/* Actualiser */}
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold font-mono text-xs transition-all active:scale-95 cursor-pointer disabled:opacity-60"
              title="Recharger les 200 derniers logs depuis l'API"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} />
              <span>{refreshing ? "Chargement..." : "Actualiser"}</span>
            </button>

            {/* Export CSV */}
            <button
              onClick={handleExportCSV}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold font-mono text-xs transition-all active:scale-95 cursor-pointer"
              title="Exporter les logs filtrés au format CSV (Excel)"
            >
              <Download className="w-3.5 h-3.5" />
              <span>CSV</span>
            </button>

            {/* Export PDF */}
            <button
              onClick={handleExportPDF}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold font-mono text-xs transition-all active:scale-95 cursor-pointer"
              title="Imprimer / exporter les logs filtrés au format PDF"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>PDF</span>
            </button>

            {/* Réinitialiser */}
            <button
              onClick={handleResetFilters}
              disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold font-mono text-xs transition-all active:scale-95 cursor-pointer disabled:opacity-60"
              title="Vider les filtres et recharger les logs"
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
                <th className="py-2.5 px-3 w-10 text-center">
                  <Flag className="w-3 h-3 mx-auto" />
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono text-xs text-slate-700 dark:text-slate-300">
              {refreshing ? (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-slate-400">
                    <RefreshCw className="w-6 h-6 text-blue-400 mx-auto mb-2 animate-spin" />
                    <span>Actualisation en cours…</span>
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <Terminal className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-3 animate-pulse" />
                    <span>Aucun log ne correspond aux filtres saisis.</span>
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log, idx) => {
                  const isExpanded = selectedLogId === log.raw_log_id;
                  const isFlagged = flaggedIds.has(log.raw_log_id);

                  const severityConfig =
                    log.severity === "critical"
                      ? { text: "Critique", style: "text-red-500 bg-red-500/10 border-red-500/20" }
                      : log.severity === "high"
                      ? { text: "Haute", style: "text-orange-500 bg-orange-500/10 border-orange-500/20" }
                      : log.severity === "warning"
                      ? { text: "Avert.", style: "text-amber-500 bg-amber-500/10 border-amber-500/20" }
                      : { text: "Info", style: "text-blue-500 bg-blue-500/10 border-blue-500/20" };

                  const logTypeBadge = () => {
                    if (log.log_type === "auth")
                      return <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-orange-600 dark:text-orange-400 bg-orange-100/50 dark:bg-orange-950/30 border border-orange-200 dark:border-orange-900/20">SECURITY</span>;
                    if (log.log_type === "network")
                      return <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-emerald-600 dark:text-emerald-400 bg-emerald-100/50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/20">FIREWALL</span>;
                    if (log.log_type === "system")
                      return <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-blue-600 dark:text-blue-400 bg-blue-100/50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900/20">SYSTEM</span>;
                    if (log.log_type === "application")
                      return <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-red-600 dark:text-red-400 bg-red-100/50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/20">APP</span>;
                    return <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase text-purple-600 dark:text-purple-400 bg-purple-100/50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-900/20">AUDIT</span>;
                  };

                  return (
                    <React.Fragment key={log.raw_log_id || `log-${idx}`}>
                      <tr
                        onClick={() => setSelectedLogId(isExpanded ? null : log.raw_log_id)}
                        className={`transition-all cursor-pointer ${
                          isFlagged
                            ? "bg-amber-50 dark:bg-amber-900/10 hover:bg-amber-100/80 dark:hover:bg-amber-900/20"
                            : isExpanded
                            ? "bg-slate-50 dark:bg-slate-800/10 hover:bg-slate-100 dark:hover:bg-slate-800/20"
                            : "hover:bg-slate-50 dark:hover:bg-slate-800/20"
                        }`}
                      >
                        <td className="py-2.5 px-6 text-center text-slate-400 shrink-0 select-none">
                          {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-blue-500" /> : <ChevronDown className="w-3.5 h-3.5" />}
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
                          <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-bold border ${severityConfig.style}`}>
                            {severityConfig.text}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-center" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={(e) => toggleFlag(log.raw_log_id, e)}
                            title={isFlagged ? "Retirer le signalement" : "Marquer comme suspect"}
                            className={`p-1 rounded transition-colors ${
                              isFlagged
                                ? "text-amber-500 hover:text-amber-400"
                                : "text-slate-300 hover:text-amber-500 dark:text-slate-600 dark:hover:text-amber-500"
                            }`}
                          >
                            <Flag className={`w-3.5 h-3.5 ${isFlagged ? "fill-current" : ""}`} />
                          </button>
                        </td>
                      </tr>

                      {/* Expandable structured detail view */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={8} className="p-0 bg-slate-50/50 dark:bg-slate-900/10">
                            <div className="px-12 py-5 border-t border-b border-slate-100 dark:border-slate-800/60">
                              <div className="flex items-center justify-between mb-3 text-[10px] uppercase text-slate-400 dark:text-slate-500 font-bold tracking-wider">
                                <span className="flex items-center gap-1.5">
                                  <Eye className="w-3.5 h-3.5" /> Détail de l'événement
                                </span>
                                <span className="font-mono">{log.raw_log_id}</span>
                              </div>
                              <div className="bg-white dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden text-xs font-mono">
                                {[
                                  { label: "Message brut", value: log.raw_message },
                                  { label: "Hôte",         value: log.host },
                                  { label: "Action",       value: log.event_action },
                                  { label: "IP source",    value: log.source_ip },
                                  { label: "Criticité",    value: log.severity },
                                  { label: "Horodatage",   value: log["@timestamp"] },
                                ].map(({ label, value }) => (
                                  <div
                                    key={label}
                                    className="flex border-b border-slate-100 dark:border-slate-800 last:border-0"
                                  >
                                    <div className="w-32 shrink-0 px-4 py-2.5 bg-slate-50 dark:bg-slate-900 text-[10px] font-bold uppercase tracking-wide text-slate-400 dark:text-slate-500">
                                      {label}
                                    </div>
                                    <div className="px-4 py-2.5 text-slate-700 dark:text-slate-300 break-all leading-relaxed">
                                      {value || "—"}
                                    </div>
                                  </div>
                                ))}
                              </div>
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
