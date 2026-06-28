/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  User,
  ShieldAlert,
  Search,
  Activity,
  UserCheck,
  TrendingUp,
  Fingerprint,
  Calendar,
  Layers
} from 'lucide-react';
import api from '../../Services/api';
import type { UebaAnomaly } from '../../types';

export default function UebaView() {
  const [anomalies, setAnomalies] = useState<UebaAnomaly[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  useEffect(() => {
    async function loadAnomalies() {
      try {
        const res = await api.getAnomalies();
        setAnomalies(res);
      } catch (err) {
        console.error('Erreur chargement anomalies UEBA', err);
      } finally {
        setLoading(false);
      }
    }
    loadAnomalies();
  }, []);

  if (loading) {
    return (
      <div id="ueba-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  // Filter anomalies
  const filteredAnomalies = anomalies.filter((anom) => {
    const matchesSearch = anom.user_or_entity.toLowerCase().includes(search.toLowerCase()) || 
                          anom.anomaly_description.toLowerCase().includes(search.toLowerCase());
    const matchesCategory = categoryFilter === 'ALL' || anom.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  return (
    <div id="ueba-view-container" className="p-6 space-y-6 overflow-y-auto h-full pb-16">
      
      {/* Search and Filters Header */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <span>Détection Comportementale & Anomalies (UEBA)</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Surveillance continue des entités (utilisateurs et machines) par apprentissage automatique pour identifier les déviations.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 font-mono">
          {/* Search box */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Rechercher utilisateur..."
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
            <option value="Suspicious Working Hours">Heures suspectes</option>
            <option value="Data Volume Peak">Volume de données</option>
            <option value="Unusual SSH Country">SSH Pays inhabituel</option>
            <option value="Privilege Escalation">Escalade de privilèges</option>
          </select>
        </div>
      </div>

      {/* Anomalies Cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {filteredAnomalies.length === 0 ? (
          <div className="col-span-full py-16 text-center text-slate-400">
            <Fingerprint className="w-10 h-10 text-slate-300 dark:text-slate-700 mx-auto mb-3 animate-pulse" />
            <span>Aucune anomalie comportementale ne correspond à vos critères de filtrage.</span>
          </div>
        ) : (
          filteredAnomalies.map((anom) => {
            // Colors based on risk score
            const isHighRisk = anom.risk_score >= 80;
            const isMediumRisk = anom.risk_score >= 50 && anom.risk_score < 80;
            const scoreColor = isHighRisk 
              ? 'text-red-500 bg-red-500/10 border-red-500/20' 
              : isMediumRisk 
              ? 'text-orange-500 bg-orange-500/10 border-orange-500/20' 
              : 'text-blue-500 bg-blue-500/10 border-blue-500/20';

            return (
              <div 
                key={anom.id} 
                className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between gap-4 hover:scale-[1.005] transition-all"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-500 flex items-center justify-center">
                        <User className="w-4.5 h-4.5" />
                      </div>
                      <div>
                        <h5 className="font-bold text-xs text-slate-800 dark:text-slate-200">
                          {anom.user_or_entity}
                        </h5>
                        <span className="text-[10px] font-mono font-bold text-slate-400 dark:text-slate-500 uppercase">
                          Type: {anom.type}
                        </span>
                      </div>
                    </div>

                    <div className={`px-3 py-1 rounded-full text-xs font-bold border font-mono ${scoreColor}`}>
                      Risk Score: {anom.risk_score}
                    </div>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-305 leading-relaxed font-sans">
                    {anom.anomaly_description}
                  </p>
                </div>

                <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800/60 pt-3.5 mt-1 text-[10px] text-slate-400 font-mono font-bold">
                  <div className="flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-slate-400" />
                    <span>{anom.category}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Calendar className="w-3.5 h-3.5 text-slate-400" />
                    <span>{new Date(anom.timestamp).toLocaleString()}</span>
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
