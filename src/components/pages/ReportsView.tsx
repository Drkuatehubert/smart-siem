/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  FileText,
  Plus,
  Download,
  Calendar,
  Layers,
  Search,
  CheckCircle,
  Database,
  ArrowRight,
  TrendingUp,
  X
} from 'lucide-react';
import api from '../../Services/api';
import type { SecurityReport, UserRole } from '../../types';

interface ReportsViewProps {
  activeRole: UserRole;
}

export default function ReportsView({ activeRole }: ReportsViewProps) {
  const [reports, setReports] = useState<SecurityReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  
  // Generation report form
  const [showModal, setShowModal] = useState(false);
  const [title, setTitle] = useState('');
  const [type, setType] = useState<SecurityReport['type']>('DAILY');
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    async function loadReports() {
      try {
        const res = await api.getReports();
        setReports(res);
      } catch (err) {
        console.error('Erreur chargement des rapports', err);
      } finally {
        setLoading(false);
      }
    }
    loadReports();
  }, []);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;

    setGenerating(true);
    try {
      // Simulate rendering latency
      await new Promise((resolve) => setTimeout(resolve, 1800));
      const newRep = await api.generateReport(title, type, 'Dominique', activeRole);
      setReports((prev) => [newRep, ...prev]);
      setShowModal(false);
      setTitle('');
      setType('DAILY');
    } catch (err) {
      console.error('Erreur génération du rapport', err);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownloadReport = (rep: SecurityReport) => {
    // Produce mock text download representing the SIEM report payload
    const payload = {
      report_id: rep.id,
      title: rep.title,
      type: rep.type,
      generated_by: rep.generated_by,
      timestamp: rep.created_at,
      metrics: {
        total_logs_analyzed: 457910,
        unauthorized_ssh_attacks: 1450,
        mitigated_c2_threats: 4,
        patching_sla_percentage: '94.2%'
      },
      verdict: 'Excellent global stance with minor open vulnerabilities on development machines.'
    };

    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(payload, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `${rep.title.replace(/\s+/g, '_')}_${rep.id}.json`);
    document.body.appendChild(dlAnchor);
    dlAnchor.click();
    dlAnchor.remove();
  };

  if (loading) {
    return (
      <div id="reports-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const filteredReports = reports.filter((rep) => {
    return rep.title.toLowerCase().includes(search.toLowerCase()) || 
           rep.type.toLowerCase().includes(search.toLowerCase());
  });

  return (
    <div id="reports-view" className="p-6 space-y-6 overflow-y-auto h-full pb-16 relative">
      
      {/* Search and Action Bar */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <FileText className="w-4.5 h-4.5 text-blue-600 dark:text-blue-400" />
            <span>Synthèses d'Activité & Rapports d'Audit</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Générez ou téléchargez les synthèses d'activité de sécurité, rapports règlementaires RGPD et analyses d'audit ISO.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Rechercher rapport..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 w-52 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
            />
          </div>

          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer shadow-md hover:shadow-blue-500/20"
          >
            <Plus className="w-4 h-4" />
            <span>Générer un rapport</span>
          </button>
        </div>
      </div>

      {/* Reports Listing table */}
      <div className="bg-white dark:bg-[#1E293B] border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
        
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/30 text-[10px] font-bold uppercase text-slate-400 dark:text-slate-500">
                <th className="py-3.5 px-6">Titre du Rapport</th>
                <th className="py-3.5 px-4">Périodicité / Type</th>
                <th className="py-3.5 px-4">Créé par</th>
                <th className="py-3.5 px-4">Format</th>
                <th className="py-3.5 px-4 text-center">Taille</th>
                <th className="py-3.5 px-4">Date de génération</th>
                <th className="py-3.5 px-6 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-700 dark:text-slate-300">
              {filteredReports.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <FileText className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2 animate-pulse" />
                    <span>Aucun rapport trouvé.</span>
                  </td>
                </tr>
              ) : (
                filteredReports.map((rep) => {
                  const typeColors = 
                    rep.type === 'COMPLIANCE' ? 'text-blue-500 bg-blue-500/10 border-blue-500/20' :
                    rep.type === 'MONTHLY' ? 'text-red-500 bg-red-500/10 border-red-500/20' :
                    rep.type === 'WEEKLY' ? 'text-orange-500 bg-orange-500/10 border-orange-500/20' :
                    'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';

                  return (
                    <tr key={rep.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/10 transition-colors">
                      <td className="py-3.5 px-6 font-bold text-slate-900 dark:text-slate-100 font-sans">
                        {rep.title}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold border uppercase ${typeColors}`}>
                          {rep.type}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-500">{rep.generated_by}</td>
                      <td className="py-3.5 px-4 font-bold text-slate-450 uppercase">{rep.format}</td>
                      <td className="py-3.5 px-4 text-center text-slate-500">{rep.size}</td>
                      <td className="py-3.5 px-4 text-slate-400">
                        {new Date(rep.created_at).toLocaleString()}
                      </td>
                      <td className="py-3.5 px-6 text-right">
                        <button
                          onClick={() => handleDownloadReport(rep)}
                          className="flex items-center gap-1 ml-auto px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-950 text-blue-600 dark:text-blue-400 font-bold transition-all active:scale-95 cursor-pointer"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Télécharger</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

      </div>

      {/* GENERATE REPORT MODAL */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#1E293B] w-full max-w-md rounded-xl border border-slate-200 dark:border-slate-800 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/60 pb-3">
              <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <FileText className="w-4 h-4 text-blue-500" />
                <span>Générer un rapport de sécurité</span>
              </h4>
              <button 
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4.5 h-4.5" />
              </button>
            </div>

            <form onSubmit={handleGenerate} className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Titre du Rapport</label>
                <input
                  type="text"
                  required
                  placeholder="ex: Rapport mensuel des vulnérabilités critiques"
                  value={title}
                  disabled={generating}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 font-sans"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Type / Périodicité</label>
                <select
                  value={type}
                  disabled={generating}
                  onChange={(e) => setType(e.target.value as any)}
                  className="w-full px-3 py-2.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer font-mono"
                >
                  <option value="DAILY">Daily (Quotidien)</option>
                  <option value="WEEKLY">Weekly (Hebdomadaire)</option>
                  <option value="MONTHLY">Monthly (Mensuel)</option>
                  <option value="COMPLIANCE">Compliance (Conformité règlementaire)</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-100 dark:border-slate-800/60">
                <button
                  type="button"
                  disabled={generating}
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900 transition-all cursor-pointer"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  disabled={generating}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-75 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer shadow-md flex items-center gap-1.5"
                >
                  {generating ? (
                    <>
                      <Plus className="w-4.5 h-4.5 animate-spin" />
                      <span>Rendu du PDF...</span>
                    </>
                  ) : (
                    <>
                      <span>Lancer la génération</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
