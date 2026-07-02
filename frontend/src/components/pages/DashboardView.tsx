import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  Terminal,
  Server,
  Activity,
  AlertTriangle,
  ArrowRight,
  ShieldCheck,
  UserCheck,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Legend,
} from "recharts";
import api from "../../Services/api";
import type {
  LogEvent,
  Incident,
  EndpointAgent,
  UebaProfile,
} from "../../types";
import type { DashboardSummary } from "../../Services/dashboardService";

export default function DashboardView() {
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [agents, setAgents] = useState<EndpointAgent[]>([]);
  const [profiles, setProfiles] = useState<UebaProfile[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchData() {
      try {
        const [logsRes, incidentsRes, agentsRes, profilesRes, summaryRes] =
          await Promise.all([
            api.getLogs(),
            api.getIncidents(),
            api.getAgents(),
            api.getUebaProfiles(),
            api.getDashboardSummary(),
          ]);
        setLogs(logsRes);
        setIncidents(incidentsRes);
        setAgents(agentsRes);
        setProfiles(profilesRes);
        setSummary(summaryRes);
      } catch (err) {
        console.error("Erreur chargement dashboard data", err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return (
      <div
        id="dashboard-loading"
        className="flex-1 flex items-center justify-center p-8 h-full"
      >
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const totalLogs = summary?.total_logs_24h ?? logs.length;
  const activeIncidents = incidents.filter((i) => i.status !== "closed").length;
  const openAlerts = summary?.total_alerts_open ?? activeIncidents;
  const criticalAlerts =
    summary?.critical_alerts ??
    incidents.filter((i) => i.severity === "critical").length;
  const activeAgents = agents.filter((a) => a.status === "ONLINE").length;
  const agentUptime =
    agents.length > 0 ? Math.round((activeAgents / agents.length) * 100) : 0;
  const avgRiskScore =
    profiles.length > 0
      ? Math.round(
          profiles.reduce((acc, curr) => acc + curr.risk_score_current, 0) /
            profiles.length,
        )
      : 0;

  const activityData =
    summary?.log_volume_by_hour?.map((point) => ({
      time: new Date(point.hour).toLocaleTimeString("fr-FR", {
        hour: "2-digit",
        minute: "2-digit",
      }),
      Volume: point.count,
    })) ?? [];

  const alertSeverityData =
    summary?.alerts_by_level?.map((item) => ({
      name: item.niveau,
      count: item.count,
      fill:
        item.niveau === "CRITICAL"
          ? "#ef4444"
          : item.niveau === "HIGH"
            ? "#f97316"
            : item.niveau === "WARNING"
              ? "#f59e0b"
              : "#3b82f6",
    })) ?? [];

  const severityData = [
    {
      name: "Critique",
      count: incidents.filter((i) => i.severity === "critical").length,
      fill: "#ef4444",
    },
    {
      name: "Haute",
      count: incidents.filter((i) => i.severity === "high").length,
      fill: "#f97316",
    },
    {
      name: "Moyenne",
      count: incidents.filter((i) => i.severity === "warning").length,
      fill: "#f59e0b",
    },
    {
      name: "Basse",
      count: incidents.filter((i) => i.severity === "info").length,
      fill: "#3b82f6",
    },
  ];

  return (
    <div
      id="dashboard-view"
      className="p-6 space-y-6 overflow-y-auto h-full pb-16"
    >
      {/* 4 Stats Cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Logs Card */}
        <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between hover:scale-[1.01] transition-transform">
          <div className="space-y-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              Journaux collectés
            </span>
            <h3 className="text-2xl font-bold tracking-tight text-slate-800 dark:text-slate-100 font-mono">
              {totalLogs.toLocaleString()}
            </h3>
            <p className="text-[10px] text-slate-400 dark:text-slate-500 font-medium">
              Dernières 24 heures
            </p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-blue-500/10 text-blue-500 flex items-center justify-center shrink-0">
            <Terminal className="w-6 h-6" />
          </div>
        </div>

        {/* Incidents Card */}
        <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between hover:scale-[1.01] transition-transform">
          <div className="space-y-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              Alertes actives
            </span>
            <h3 className="text-2xl font-bold tracking-tight text-slate-800 dark:text-slate-100 font-mono">
              {openAlerts}
            </h3>
            <p className="text-[10px] text-rose-500 font-bold flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" />
              <span>{criticalAlerts} alertes critiques</span>
            </p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-red-500/10 text-red-500 flex items-center justify-center shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        {/* Agents Card */}
        <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between hover:scale-[1.01] transition-transform">
          <div className="space-y-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              Hôtes & Agents EDR
            </span>
            <h3 className="text-2xl font-bold tracking-tight text-slate-800 dark:text-slate-100 font-mono">
              {activeAgents} / {agents.length}
            </h3>
            <p className="text-[10px] text-slate-400 dark:text-slate-500 font-medium">
              Disponibilité agents : {agentUptime}%
            </p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-emerald-500/10 text-emerald-500 flex items-center justify-center shrink-0">
            <Server className="w-6 h-6" />
          </div>
        </div>

        {/* UEBA Score Card */}
        <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between hover:scale-[1.01] transition-transform">
          <div className="space-y-1">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              Niveau de Risque UEBA
            </span>
            <h3 className="text-2xl font-bold tracking-tight text-slate-800 dark:text-slate-100 font-mono">
              {avgRiskScore}{" "}
              <span className="text-xs text-slate-400 font-normal">/ 100</span>
            </h3>
            <p className="text-[10px] text-amber-500 font-bold flex items-center gap-1">
              <Activity className="w-3 h-3 animate-pulse" />
              <span>Anomalies comportementales</span>
            </p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-amber-500/10 text-amber-500 flex items-center justify-center shrink-0">
            <UserCheck className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Main Charts grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Interactive Timeline of Security events (2/3 width) */}
        <div className="lg:col-span-2 bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
          <div>
            <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100">
              Activité des flux de logs (Temps Réel)
            </h4>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
              Analyse volumétrique par catégorie de collecteurs sur les
              dernières heures.
            </p>
          </div>
          <div className="h-72 w-full font-mono text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={activityData}
                margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="colorNet" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorEnd" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#e2e8f0"
                  className="dark:hidden"
                />
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#334155"
                  className="hidden dark:block"
                />
                <XAxis dataKey="time" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderRadius: "8px",
                    border: "none",
                    color: "#fff",
                  }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="Volume"
                  stroke="#3b82f6"
                  fillOpacity={1}
                  fill="url(#colorNet)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right: Alerts Breakdown by Severity (1/3 width) */}
        <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
          <div>
            <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100">
              Gravité des Alertes
            </h4>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
              Répartition des incidents actifs classés par niveau de sévérité.
            </p>
          </div>
          <div className="h-72 w-full font-mono text-xs">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={alertSeverityData.length > 0 ? alertSeverityData : severityData}
                layout="vertical"
                margin={{ top: 10, right: 10, left: -10, bottom: 5 }}
              >
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#e2e8f0"
                  className="dark:hidden"
                />
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#334155"
                  className="hidden dark:block"
                />
                <XAxis type="number" stroke="#94a3b8" />
                <YAxis
                  dataKey="name"
                  type="category"
                  stroke="#94a3b8"
                  width={60}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderRadius: "8px",
                    border: "none",
                    color: "#fff",
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={24} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent incidents & threats split view */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Active Incidents List */}
        <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100">
              Incidents Actifs Recents
            </h4>
            <span className="text-xs text-blue-500 hover:underline cursor-pointer flex items-center gap-1">
              <span>Voir tout</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </span>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-800 space-y-3.5">
            {incidents.slice(0, 3).map((inc) => {
              const badgeColors =
                inc.severity === "critical"
                  ? "text-red-500 bg-red-500/10 border-red-500/20"
                  : inc.severity === "high"
                    ? "text-orange-500 bg-orange-500/10 border-orange-500/20"
                    : inc.severity === "warning"
                      ? "text-amber-500 bg-amber-500/10 border-amber-500/20"
                      : "text-blue-500 bg-blue-500/10 border-blue-500/20";

              return (
                <div
                  key={inc.id}
                  className="pt-3.5 first:pt-0 flex items-start justify-between gap-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[9px] font-bold border ${badgeColors} font-mono`}
                      >
                        {inc.severity}
                      </span>
                      <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
                        {inc.title}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-450 dark:text-slate-400 line-clamp-1">
                      {inc.root_cause || "Aucune cause racine définie"}
                    </p>
                  </div>
                  <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono shrink-0">
                    {new Date(inc.opened_at).toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Security Posture Score */}
        <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between">
          <div className="space-y-1">
            <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100">
              État de la Posture de Sécurité
            </h4>
            <p className="text-xs text-slate-400 dark:text-slate-500">
              Évaluation continue basée sur les règles, la conformité et les
              vulnérabilités.
            </p>
          </div>

          <div className="py-6 flex items-center justify-center gap-6">
            <div className="relative w-28 h-28 flex items-center justify-center">
              {/* Simple CSS Circular indicator */}
              <div className="absolute inset-0 rounded-full border-8 border-slate-100 dark:border-slate-850"></div>
              <div className="absolute inset-0 rounded-full border-8 border-emerald-500 border-t-transparent border-r-transparent animate-spin-slow"></div>
              <div className="text-center">
                <span className="text-3xl font-extrabold text-slate-800 dark:text-slate-100 font-mono">
                  82
                </span>
                <span className="text-xs text-slate-400 block font-semibold">
                  %
                </span>
              </div>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex items-center gap-2 font-semibold">
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
                <span>Niveau global : Optimal</span>
              </div>
              <p className="text-[11px] text-slate-450 dark:text-slate-400 leading-relaxed max-w-xs">
                Moteur de corrélation actif. Agents de télémétrie stables. 1
                vulnérabilité critique en cours de remédiation (CVE-2024-3094).
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
