import React, { useCallback, useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Clock,
  Globe,
  RefreshCw,
  Search,
  Server,
  User,
  X,
} from "lucide-react";
import api from "../../Services/api";
import type { UebaProfile } from "../../types";

// ── Helpers ──────────────────────────────────────────────────────────────────

function riskInfo(score: number) {
  if (score <= 20) return { label: "Faible",   cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400" };
  if (score <= 50) return { label: "Modéré",   cls: "bg-amber-100   text-amber-700   dark:bg-amber-900/30   dark:text-amber-400" };
  if (score <= 80) return { label: "Élevé",    cls: "bg-red-100     text-red-700     dark:bg-red-900/30     dark:text-red-400" };
  return               { label: "Critique", cls: "bg-rose-900 text-rose-200" };
}

function RiskBadge({ score }: { score: number }) {
  const { label, cls } = riskInfo(score);
  return <span className={`inline-block px-2 py-0.5 rounded-full text-[11px] font-bold ${cls}`}>{label}</span>;
}

function ScoreGauge({ score }: { score: number }) {
  const r = 38;
  const circ = 2 * Math.PI * r;
  const dash = (Math.min(score, 100) / 100) * circ;
  const stroke =
    score <= 20 ? "#10b981" : score <= 50 ? "#f59e0b" : score <= 80 ? "#ef4444" : "#881337";
  return (
    <div className="relative inline-flex items-center justify-center w-24 h-24">
      <svg className="absolute inset-0 -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#e2e8f0" strokeWidth="10"
          className="dark:stroke-slate-700" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={stroke} strokeWidth="10"
          strokeDasharray={`${dash.toFixed(1)} ${circ.toFixed(1)}`} strokeLinecap="round"
          style={{ transition: "stroke-dasharray .4s ease" }} />
      </svg>
      <span className="text-xl font-bold text-slate-800 dark:text-slate-100">{score}</span>
    </div>
  );
}

// ── Detail panel ─────────────────────────────────────────────────────────────

function DetailPanel({ profile, onClose }: { profile: UebaProfile; onClose: () => void }) {
  const isUser = profile.entity_type === "user";
  const peak = profile.typical_login_hours?.peak_hours ?? [];
  const anomalyNum =
    profile.anomalies_detected.length > 0
      ? (profile.anomalies_detected[0].description.match(/\d+/)?.[0] ?? "0")
      : "0";
  const prevScore =
    profile.risk_score_history.length > 1
      ? profile.risk_score_history[0].score
      : null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-80 bg-white dark:bg-slate-900 shadow-2xl border-l border-slate-200 dark:border-slate-700 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-700 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <div
            className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
              isUser
                ? "bg-emerald-100 dark:bg-emerald-900/40"
                : "bg-violet-100 dark:bg-violet-900/40"
            }`}
          >
            {isUser ? (
              <User className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <Server className="w-4 h-4 text-violet-600 dark:text-violet-400" />
            )}
          </div>
          <div className="min-w-0">
            <p className="font-bold text-sm text-slate-800 dark:text-slate-100 truncate">
              {profile.entity_id}
            </p>
            <p className="text-xs text-slate-400">{isUser ? "Utilisateur" : "Machine"}</p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 ml-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors shrink-0"
        >
          <X className="w-4 h-4 text-slate-400" />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-5">
        {/* Score */}
        <div className="flex flex-col items-center gap-2">
          <ScoreGauge score={profile.risk_score_current} />
          <RiskBadge score={profile.risk_score_current} />
        </div>

        {/* Quick stats */}
        <div className="grid grid-cols-2 gap-2">
          {[
            {
              label: "Événements/j",
              value: profile.avg_daily_events.toFixed(0),
              icon: <Activity className="w-3 h-3 text-blue-400" />,
            },
            {
              label: "Anomalies 7j",
              value: anomalyNum,
              icon: <AlertTriangle className="w-3 h-3 text-amber-400" />,
            },
            {
              label: "Score précédent",
              value: prevScore != null ? String(prevScore) : "—",
              icon: <Activity className="w-3 h-3 text-slate-400" />,
            },
            {
              label: "IPs connues",
              value: String(profile.typical_source_ips.length),
              icon: <Globe className="w-3 h-3 text-emerald-400" />,
            },
          ].map(({ label, value, icon }) => (
            <div key={label} className="bg-slate-50 dark:bg-slate-800 rounded-lg p-2.5">
              <div className="flex items-center gap-1 text-[10px] text-slate-400 mb-1">
                {icon}
                <span>{label}</span>
              </div>
              <p className="font-bold text-sm text-slate-700 dark:text-slate-200">{value}</p>
            </div>
          ))}
        </div>

        {/* Peak hours */}
        {peak.length > 0 && (
          <div>
            <p className="flex items-center gap-1.5 text-xs font-semibold text-slate-600 dark:text-slate-300 mb-2">
              <Clock className="w-3.5 h-3.5 text-blue-400" />
              Heures d'activité typiques
            </p>
            <div className="flex flex-wrap gap-1">
              {peak.map((h) => (
                <span
                  key={h}
                  className="text-xs font-mono bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 px-2 py-0.5 rounded border border-blue-200 dark:border-blue-800"
                >
                  {String(h).padStart(2, "0")}h
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Source IPs */}
        {profile.typical_source_ips.length > 0 && (
          <div>
            <p className="flex items-center gap-1.5 text-xs font-semibold text-slate-600 dark:text-slate-300 mb-2">
              <Globe className="w-3.5 h-3.5 text-emerald-400" />
              IPs sources connues
            </p>
            <div className="space-y-1">
              {profile.typical_source_ips.slice(0, 8).map((ip) => (
                <div
                  key={ip}
                  className="text-xs font-mono text-slate-600 dark:text-slate-300 px-2 py-1 bg-slate-50 dark:bg-slate-800 rounded"
                >
                  {ip}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Anomalies */}
        {profile.anomalies_detected.length > 0 && (
          <div>
            <p className="flex items-center gap-1.5 text-xs font-semibold text-red-600 dark:text-red-400 mb-2">
              <AlertTriangle className="w-3.5 h-3.5" />
              Anomalies détectées
            </p>
            <div className="space-y-1.5">
              {profile.anomalies_detected.map((a, i) => (
                <div
                  key={i}
                  className="text-xs text-slate-600 dark:text-slate-300 px-2 py-2 bg-red-50 dark:bg-red-950/20 rounded border border-red-100 dark:border-red-900/30"
                >
                  {a.description}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Accessed systems */}
        {profile.typical_accessed_systems.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-slate-600 dark:text-slate-300 mb-2">
              Systèmes accédés
            </p>
            <div className="flex flex-wrap gap-1">
              {profile.typical_accessed_systems.map((s) => (
                <span
                  key={s}
                  className="text-[10px] font-mono bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700"
                >
                  {s}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="text-xs text-slate-400 border-t border-slate-100 dark:border-slate-800 pt-3 space-y-0.5">
          {profile.profile_period_start && (
            <p>
              Période : {profile.profile_period_start} → {profile.profile_period_end}
            </p>
          )}
          <p>
            Mis à jour :{" "}
            {new Date(profile.last_updated).toLocaleString("fr-FR")}
          </p>
        </div>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function UebaView() {
  const [profiles, setProfiles]   = useState<UebaProfile[]>([]);
  const [loading, setLoading]     = useState(true);
  const [computing, setComputing] = useState(false);
  const [search, setSearch]       = useState("");
  const [typeFilter, setTypeFilter] = useState<"ALL" | "user" | "machine">("ALL");
  const [selected, setSelected]   = useState<UebaProfile | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.getUebaProfiles();
      setProfiles(res);
    } catch (err) {
      console.error("UEBA load error", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleCompute = async () => {
    setComputing(true);
    try {
      await api.computeUebaProfiles();
      // Wait a moment for background task, then reload
      await new Promise((r) => setTimeout(r, 3000));
      await load();
    } catch {
      await load();
    } finally {
      setComputing(false);
    }
  };

  const filtered = profiles.filter((p) => {
    const matchType   = typeFilter === "ALL" || p.entity_type === typeFilter;
    const matchSearch = !search || p.entity_id.toLowerCase().includes(search.toLowerCase());
    return matchType && matchSearch;
  });

  const total    = profiles.length;
  const avgScore = total
    ? Math.round(profiles.reduce((s, p) => s + p.risk_score_current, 0) / total)
    : 0;
  const atRisk   = profiles.filter((p) => p.risk_score_current > 50).length;

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-5 overflow-y-auto h-full pb-16">
      {/* KPI row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[
          {
            label: "Entités surveillées",
            value: total,
            sub:   `${profiles.filter((p) => p.entity_type === "user").length} utilisateurs · ${profiles.filter((p) => p.entity_type === "machine").length} machines`,
            color: "text-blue-600 dark:text-blue-400",
          },
          {
            label: "Score de risque moyen",
            value: avgScore,
            sub:   "sur 100",
            color: avgScore > 50 ? "text-red-500" : avgScore > 20 ? "text-amber-500" : "text-emerald-500",
          },
          {
            label: "Entités à risque élevé",
            value: atRisk,
            sub:   "score > 50",
            color: atRisk > 0 ? "text-red-500" : "text-emerald-500",
          },
        ].map(({ label, value, sub, color }) => (
          <div
            key={label}
            className="bg-white dark:bg-slate-800 rounded-xl p-4 border border-slate-200 dark:border-slate-700 shadow-sm"
          >
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">{label}</p>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
            <p className="text-xs text-slate-400 mt-0.5">{sub}</p>
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-3 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[160px]">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Rechercher entité..."
            className="w-full pl-8 pr-3 py-2 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value as typeof typeFilter)}
          className="px-3 py-2 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
        >
          <option value="ALL">Tous les types</option>
          <option value="user">Utilisateurs</option>
          <option value="machine">Machines</option>
        </select>

        <button
          onClick={handleCompute}
          disabled={computing}
          className="ml-auto flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${computing ? "animate-spin" : ""}`} />
          {computing ? "Calcul en cours..." : "Recalculer les profils"}
        </button>
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50">
                {["Entité", "Type", "Niveau de risque", "Score", "Anomalies 7j", "Moy. événements/j", "Dernière anomalie"].map(
                  (h) => (
                    <th
                      key={h}
                      className="px-4 py-3 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-slate-400">
                    Aucun profil UEBA trouvé
                  </td>
                </tr>
              ) : (
                filtered.map((p) => {
                  const isUser = p.entity_type === "user";
                  const anomalyNum =
                    p.anomalies_detected.length > 0
                      ? (p.anomalies_detected[0].description.match(/\d+/)?.[0] ?? "0")
                      : "0";
                  const lastAnomaly =
                    p.anomalies_detected[0]?.timestamp
                      ? new Date(p.anomalies_detected[0].timestamp).toLocaleDateString("fr-FR")
                      : "—";
                  const isActive = selected?.entity_id === p.entity_id;
                  return (
                    <tr
                      key={p.entity_id}
                      onClick={() => setSelected(isActive ? null : p)}
                      className={`cursor-pointer transition-colors ${
                        isActive
                          ? "bg-blue-50 dark:bg-blue-900/20"
                          : "hover:bg-slate-50 dark:hover:bg-slate-700/30"
                      }`}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div
                            className={`w-6 h-6 rounded flex items-center justify-center shrink-0 ${
                              isUser
                                ? "bg-emerald-100 dark:bg-emerald-900/40"
                                : "bg-violet-100 dark:bg-violet-900/40"
                            }`}
                          >
                            {isUser ? (
                              <User className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                            ) : (
                              <Server className="w-3 h-3 text-violet-600 dark:text-violet-400" />
                            )}
                          </div>
                          <span className="font-medium text-slate-700 dark:text-slate-200 max-w-[160px] truncate">
                            {p.entity_id}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-slate-500 dark:text-slate-400">
                        {isUser ? "Utilisateur" : "Machine"}
                      </td>
                      <td className="px-4 py-3">
                        <RiskBadge score={p.risk_score_current} />
                      </td>
                      <td className="px-4 py-3 font-bold text-slate-700 dark:text-slate-200">
                        {p.risk_score_current}
                      </td>
                      <td className="px-4 py-3 text-slate-600 dark:text-slate-300">
                        {anomalyNum}
                      </td>
                      <td className="px-4 py-3 text-slate-600 dark:text-slate-300">
                        {p.avg_daily_events.toFixed(0)}
                      </td>
                      <td className="px-4 py-3 text-slate-500 dark:text-slate-400">
                        {lastAnomaly}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {filtered.length > 0 && (
          <div className="px-4 py-2 border-t border-slate-100 dark:border-slate-700 text-xs text-slate-400">
            {filtered.length} entité{filtered.length > 1 ? "s" : ""} affichée{filtered.length > 1 ? "s" : ""}
            {filtered.length < total ? ` sur ${total}` : ""}
          </div>
        )}
      </div>

      {/* Detail panel overlay */}
      {selected && (
        <>
          <div
            className="fixed inset-0 bg-black/20 z-40"
            onClick={() => setSelected(null)}
          />
          <DetailPanel profile={selected} onClose={() => setSelected(null)} />
        </>
      )}
    </div>
  );
}
