/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from "react";
import {
  User,
  ShieldAlert,
  Search,
  Activity,
  UserCheck,
  TrendingUp,
  Fingerprint,
  Calendar,
  Layers,
  Globe,
  Server,
  Clock,
  Database,
  AlertTriangle,
} from "lucide-react";
import api from "../../Services/api";
import type { UebaProfile } from "../../types";

export default function UebaView() {
  const [profiles, setProfiles] = useState<UebaProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("ALL");

  useEffect(() => {
    async function loadProfiles() {
      try {
        const res = await api.getUebaProfiles();
        setProfiles(res);
      } catch (err) {
        console.error("Erreur chargement profils UEBA", err);
      } finally {
        setLoading(false);
      }
    }
    loadProfiles();
  }, []);

  if (loading) {
    return (
      <div
        id="ueba-loading"
        className="flex-1 flex items-center justify-center p-8 h-full"
      >
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  // Derive category from first anomaly description for filter options
  const allCategories = Array.from(
    new Set(
      profiles.flatMap((p) =>
        p.anomalies_detected.map((a) => {
          if (a.description.toLowerCase().includes("exfiltration"))
            return "Exfiltration de données";
          if (a.description.toLowerCase().includes("scan"))
            return "Scan réseau";
          if (
            a.description.toLowerCase().includes("ssh") ||
            a.description.toLowerCase().includes("authentification")
          )
            return "Authentification suspecte";
          return "Autre";
        }),
      ),
    ),
  );

  // Filter profiles
  const filteredProfiles = profiles.filter((profile) => {
    const anomalyDescriptions = profile.anomalies_detected
      .map((a) => a.description)
      .join(" ");
    const matchesSearch =
      profile.entity_id.toLowerCase().includes(search.toLowerCase()) ||
      profile.entity_type.toLowerCase().includes(search.toLowerCase()) ||
      anomalyDescriptions.toLowerCase().includes(search.toLowerCase());

    const matchesCategory =
      categoryFilter === "ALL" ||
      profile.anomalies_detected.some((a) => {
        const cat = a.description.toLowerCase().includes("exfiltration")
          ? "Exfiltration de données"
          : a.description.toLowerCase().includes("scan")
            ? "Scan réseau"
            : a.description.toLowerCase().includes("ssh") ||
                a.description.toLowerCase().includes("authentification")
              ? "Authentification suspecte"
              : "Autre";
        return cat === categoryFilter;
      });

    return matchesSearch && matchesCategory;
  });

  return (
    <div
      id="ueba-view-container"
      className="p-6 space-y-6 overflow-y-auto h-full pb-16"
    >
      {/* Search and Filters Header */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <span>Détection Comportementale & Profils UEBA</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Surveillance continue des entités (utilisateurs et machines) par
            apprentissage automatique pour identifier les déviations.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 font-mono">
          {/* Search box */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Rechercher entité..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 w-52 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
            />
          </div>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">Toutes catégories</option>
            {allCategories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Profile Cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {filteredProfiles.length === 0 ? (
          <div className="col-span-full py-16 text-center text-slate-400">
            <Fingerprint className="w-10 h-10 text-slate-300 dark:text-slate-700 mx-auto mb-3 animate-pulse" />
            <span>
              Aucun profil UEBA ne correspond à vos critères de filtrage.
            </span>
          </div>
        ) : (
          filteredProfiles.map((profile) => {
            // Colors based on risk score
            const isHighRisk = profile.risk_score_current >= 80;
            const isMediumRisk =
              profile.risk_score_current >= 50 &&
              profile.risk_score_current < 80;
            const scoreColor = isHighRisk
              ? "text-red-500 bg-red-500/10 border-red-500/20"
              : isMediumRisk
                ? "text-orange-500 bg-orange-500/10 border-orange-500/20"
                : "text-blue-500 bg-blue-500/10 border-blue-500/20";

            const isUser = profile.entity_type === "user";
            const entityIconColor = isUser
              ? "text-emerald-500 bg-emerald-500/10"
              : "text-violet-500 bg-violet-500/10";

            return (
              <div
                key={profile.entity_id}
                className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between gap-4 hover:scale-[1.005] transition-all"
              >
                <div className="space-y-3">
                  {/* Header */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div
                        className={`w-8 h-8 rounded-lg flex items-center justify-center ${entityIconColor}`}
                      >
                        {isUser ? (
                          <User className="w-4.5 h-4.5" />
                        ) : (
                          <Server className="w-4.5 h-4.5" />
                        )}
                      </div>
                      <div>
                        <h5 className="font-bold text-xs text-slate-800 dark:text-slate-200">
                          {profile.entity_id}
                        </h5>
                        <span className="text-[10px] font-mono font-bold text-slate-400 dark:text-slate-500 uppercase">
                          {profile.entity_type === "user"
                            ? "Utilisateur"
                            : "Machine"}
                        </span>
                      </div>
                    </div>

                    <div
                      className={`px-3 py-1 rounded-full text-xs font-bold border font-mono ${scoreColor}`}
                    >
                      Risk Score: {profile.risk_score_current}
                    </div>
                  </div>

                  {/* Anomalies detected */}
                  {profile.anomalies_detected.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-red-400 uppercase tracking-wider">
                        <AlertTriangle className="w-3 h-3" />
                        <span>
                          Anomalies détectées (
                          {profile.anomalies_detected.length})
                        </span>
                      </div>
                      {profile.anomalies_detected.map((anomaly, idx) => (
                        <div
                          key={idx}
                          className="flex items-start gap-2 bg-red-50/50 dark:bg-red-950/10 p-2 rounded border border-red-100/30 dark:border-red-900/10"
                        >
                          <AlertTriangle className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                          <div className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">
                            <span className="font-semibold">
                              [{anomaly.risk_score}]
                            </span>{" "}
                            {anomaly.description}
                            <span className="block text-[10px] text-slate-400 mt-0.5">
                              {new Date(anomaly.timestamp).toLocaleString()}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Typical behavior details */}
                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <Clock className="w-3.5 h-3.5 text-blue-400" />
                      <span>
                        Heures de pointe:{" "}
                        {profile.typical_login_hours.peak_hours.join(", ")}h
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <Globe className="w-3.5 h-3.5 text-blue-400" />
                      <span>IPs: {profile.typical_source_ips.join(", ")}</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <Activity className="w-3.5 h-3.5 text-emerald-400" />
                      <span>{profile.avg_daily_events} événements/j</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <Database className="w-3.5 h-3.5 text-emerald-400" />
                      <span>{profile.avg_daily_data_volume_mb} Mo/j</span>
                    </div>
                  </div>

                  {/* Typical accessed systems */}
                  {profile.typical_accessed_systems.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {profile.typical_accessed_systems.map((sys) => (
                        <span
                          key={sys}
                          className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700 font-mono"
                        >
                          {sys}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800/60 pt-3.5 mt-1 text-[10px] text-slate-400 font-mono font-bold">
                  <div className="flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-slate-400" />
                    <span>
                      {profile.entity_type === "user"
                        ? "Profil utilisateur"
                        : "Profil machine"}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Calendar className="w-3.5 h-3.5 text-slate-400" />
                    <span>
                      Mis à jour:{" "}
                      {new Date(profile.last_updated).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
