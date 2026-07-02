/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Search,
  CheckCircle,
  XCircle,
  Clock,
  ExternalLink,
  Cpu,
  Bookmark,
  BookOpen,
  Calendar,
  AlertTriangle
} from 'lucide-react';
import api from '../../Services/api';
import type { Vulnerability, UserRole } from '../../types';
import { RBAC_POLICIES } from '../../utils/rbac';

interface VulnViewProps {
  activeRole: UserRole;
}

export default function VulnView({ activeRole }: VulnViewProps) {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const canEdit = RBAC_POLICIES[activeRole].canEditVuln;

  useEffect(() => {
    async function loadVulns() {
      try {
        const res = await api.getVulnerabilities();
        setVulns(res);
      } catch (err) {
        console.error('Erreur chargement vulnérabilités CVE', err);
      } finally {
        setLoading(false);
      }
    }
    loadVulns();
  }, []);

  const handleStatusChange = async (id: string, newStatus: Vulnerability['status']) => {
    if (!canEdit) return;
    try {
      const updated = await api.updateVulnStatus(id, newStatus, 'Dominique', activeRole);
      setVulns((prev) => prev.map((v) => (v.id === id ? updated : v)));
    } catch (err) {
      console.error('Erreur changement statut vulnérabilité', err);
    }
  };

  if (loading) {
    return (
      <div id="vuln-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const filteredVulns = vulns.filter((v) => {
    const matchesSearch = v.cve_id.toLowerCase().includes(search.toLowerCase()) || 
                          v.title.toLowerCase().includes(search.toLowerCase()) || 
                          v.affected_asset.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === 'ALL' || v.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div id="vuln-view" className="p-6 space-y-6 overflow-y-auto h-full pb-16">
      
      {/* Search and Filters Header */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-4.5 h-4.5 text-blue-600 dark:text-blue-400" />
            <span>Gestion des Vulnérabilités & CVE</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Identifiez et suivez le plan de remédiation des failles de sécurité recensées sur vos actifs informatiques.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="CVE, titre, actif..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 w-52 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">Toutes sévérités</option>
            <option value="CRITICAL">Critique</option>
            <option value="HIGH">Haute</option>
            <option value="MEDIUM">Moyenne</option>
            <option value="LOW">Basse</option>
          </select>
        </div>
      </div>

      {/* Vulnerabilities cards listing */}
      <div className="space-y-4">
        {filteredVulns.length === 0 ? (
          <div className="py-16 text-center text-slate-400">
            <ShieldAlert className="w-10 h-10 text-slate-300 dark:text-slate-700 mx-auto mb-3 animate-pulse" />
            <span>Aucune vulnérabilité active identifiée.</span>
          </div>
        ) : (
          filteredVulns.map((v) => {
            const isCritical = v.severity === 'CRITICAL';
            const isHigh = v.severity === 'HIGH';
            
            const sevBadge = isCritical
              ? 'text-red-500 bg-red-500/10 border-red-500/20'
              : isHigh
              ? 'text-orange-500 bg-orange-500/10 border-orange-500/20'
              : 'text-amber-500 bg-amber-500/10 border-amber-500/20';

            const statusColors = 
              v.status === 'OPEN' ? 'text-red-500 border-red-500/10 bg-red-500/5' :
              v.status === 'PATCHED' ? 'text-emerald-500 border-emerald-500/10 bg-emerald-500/5' :
              'text-slate-400 border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-900/10';

            return (
              <div 
                key={v.id} 
                className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-4 relative overflow-hidden"
              >
                {/* Visual score strip */}
                <div className={`absolute left-0 inset-y-0 w-1 ${isCritical ? 'bg-red-500' : 'bg-orange-500'}`}></div>

                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                  
                  <div className="space-y-3 flex-1">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="text-xs font-mono font-extrabold text-blue-600 dark:text-blue-400">
                        {v.cve_id}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${sevBadge}`}>
                        {v.severity} (CVSS: {v.cvss_score})
                      </span>
                      <h5 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex-1 min-w-[200px]">
                        {v.title}
                      </h5>
                    </div>

                    <p className="text-xs text-slate-650 dark:text-slate-350 leading-relaxed font-sans">
                      {v.description}
                    </p>

                    {/* Affected Asset & Remediation steps details */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1 text-xs">
                      
                      <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-lg border border-slate-150 dark:border-slate-850 space-y-1">
                        <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                          Actif concerné (Affected Asset)
                        </span>
                        <p className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                          <Cpu className="w-3.5 h-3.5 text-blue-500" />
                          <span>{v.affected_asset}</span>
                        </p>
                      </div>

                      <div className="bg-blue-50/20 dark:bg-blue-950/5 p-3 rounded-lg border border-blue-100/40 dark:border-blue-900/10 space-y-1">
                        <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                          Plan d'action & Remédiation
                        </span>
                        <p className="text-slate-700 dark:text-slate-300 font-sans leading-relaxed text-[11px]">
                          {v.remediation_steps}
                        </p>
                      </div>

                    </div>
                  </div>

                  {/* Actions Column */}
                  <div className="flex flex-row md:flex-col items-center justify-between md:justify-start gap-4 shrink-0 border-t md:border-t-0 border-slate-100 dark:border-slate-800/60 pt-3 md:pt-0">
                    <div className="space-y-1 text-right font-mono">
                      <span className="text-[9px] font-bold text-slate-400 block uppercase">
                        Statut actuel
                      </span>
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border uppercase ${statusColors}`}>
                        {v.status}
                      </span>
                    </div>

                    {canEdit ? (
                      <div className="space-y-1">
                        <span className="text-[9px] font-bold text-slate-400 block uppercase font-mono text-right md:text-left">
                          Changer statut
                        </span>
                        <select
                          value={v.status}
                          onChange={(e) => handleStatusChange(v.id, e.target.value as Vulnerability['status'])}
                          className="px-2.5 py-1.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
                        >
                          <option value="OPEN">Ouvert (Open)</option>
                          <option value="PATCHED">Corrigé (Patched)</option>
                          <option value="RISK_ACCEPTED">Risque Accepté</option>
                        </select>
                      </div>
                    ) : null}
                  </div>

                </div>

                <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800/60 pt-3 mt-4 text-[10px] font-mono text-slate-400">
                  <div className="flex items-center gap-1">
                    <Calendar className="w-3.5 h-3.5" />
                    <span>Découvert le: {new Date(v.discovered_at).toLocaleDateString()}</span>
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
