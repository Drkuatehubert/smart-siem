/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  Bookmark,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Search,
  BookOpen,
  Calendar,
  Layers,
  FileCheck,
  Edit2,
  X,
  ShieldCheck
} from 'lucide-react';
import api from '../../Services/api';
import type { ComplianceControl, UserRole } from '../../types';
import { RBAC_POLICIES } from '../../utils/rbac';

interface ComplianceViewProps {
  activeRole: UserRole;
}

export default function ComplianceView({ activeRole }: ComplianceViewProps) {
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [standardFilter, setStandardFilter] = useState('ALL');

  // Edit states
  const [selectedControl, setSelectedControl] = useState<ComplianceControl | null>(null);
  const [newStatus, setNewStatus] = useState<ComplianceControl['status']>('COMPLIANT');
  const [newEvidence, setNewEvidence] = useState('');

  const canEdit = RBAC_POLICIES[activeRole].canEditCompliance;

  useEffect(() => {
    async function loadCompliance() {
      try {
        const res = await api.getCompliance();
        setControls(res);
      } catch (err) {
        console.error('Erreur chargement gouvernance', err);
      } finally {
        setLoading(false);
      }
    }
    loadCompliance();
  }, []);

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedControl) return;

    try {
      const updated = await api.updateComplianceStatus(
        selectedControl.id,
        newStatus,
        newEvidence,
        'Dominique',
        activeRole
      );
      setControls((prev) => prev.map((c) => (c.id === selectedControl.id ? updated : c)));
      setSelectedControl(null);
    } catch (err) {
      console.error('Erreur mise à jour conformité', err);
    }
  };

  if (loading) {
    return (
      <div id="compliance-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const filteredControls = controls.filter((c) => {
    const matchesSearch = c.control_name.toLowerCase().includes(search.toLowerCase()) || 
                          c.section.toLowerCase().includes(search.toLowerCase()) || 
                          c.description.toLowerCase().includes(search.toLowerCase());
    const matchesStandard = standardFilter === 'ALL' || c.standard === standardFilter;
    return matchesSearch && matchesStandard;
  });

  return (
    <div id="compliance-view" className="p-6 space-y-6 overflow-y-auto h-full pb-16 relative">
      
      {/* Search and Filters Header */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Bookmark className="w-4.5 h-4.5 text-blue-600 dark:text-blue-400" />
            <span>Gouvernance, Risques & Conformité (GRC)</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Évaluez l'adéquation continue des configurations du SIEM avec les directives ISO 27001, RGPD et SOC 2.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Rechercher règle..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 w-52 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
            />
          </div>

          <select
            value={standardFilter}
            onChange={(e) => setStandardFilter(e.target.value)}
            className="px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">Tous les référentiels</option>
            <option value="ISO 27001">ISO 27001</option>
            <option value="RGPD">RGPD</option>
            <option value="SOC 2">SOC 2</option>
          </select>
        </div>
      </div>

      {/* Compliance cards list */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {filteredControls.length === 0 ? (
          <div className="col-span-full py-16 text-center text-slate-400">
            <Bookmark className="w-10 h-10 text-slate-300 dark:text-slate-700 mx-auto mb-3 animate-pulse" />
            <span>Aucune règle ou contrôle de conformité trouvé.</span>
          </div>
        ) : (
          filteredControls.map((c) => {
            const statusConfig = 
              c.status === 'COMPLIANT' ? { text: 'Conforme', style: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20' } :
              c.status === 'PARTIAL' ? { text: 'Partiel', style: 'text-amber-500 bg-amber-500/10 border-amber-500/20' } :
              { text: 'Non Conforme', style: 'text-rose-500 bg-rose-500/10 border-rose-500/20' };

            return (
              <div 
                key={c.id} 
                className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between gap-4 hover:scale-[1.005] transition-all relative"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold border border-blue-150 dark:border-blue-900 bg-blue-50/20 dark:bg-blue-950/20 text-blue-600 dark:text-blue-400 uppercase">
                        {c.standard}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500 font-bold">
                        {c.section}
                      </span>
                    </div>

                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-mono font-bold border uppercase ${statusConfig.style}`}>
                      {statusConfig.text}
                    </span>
                  </div>

                  <h5 className="font-bold text-xs text-slate-900 dark:text-slate-100 font-sans">
                    {c.control_name}
                  </h5>

                  <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                    {c.description}
                  </p>

                  {/* Evidence text block */}
                  <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-lg border border-slate-150 dark:border-slate-850 space-y-1">
                    <span className="text-[9px] font-mono font-bold text-slate-400 uppercase block">
                      Évidence d'Audit / Justificatif
                    </span>
                    <p className="text-slate-700 dark:text-slate-300 font-sans text-[11px] leading-relaxed">
                      {c.evidence}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800/60 pt-3 text-[10px] font-mono text-slate-400">
                  <span className="flex items-center gap-1">
                    <Calendar className="w-3.5 h-3.5" />
                    <span>Dernier audit: {new Date(c.last_audit).toLocaleDateString()}</span>
                  </span>

                  {canEdit && (
                    <button
                      onClick={() => {
                        setSelectedControl(c);
                        setNewStatus(c.status);
                        setNewEvidence(c.evidence);
                      }}
                      className="flex items-center gap-1 text-blue-500 hover:text-blue-600 font-bold uppercase transition-colors cursor-pointer"
                    >
                      <Edit2 className="w-3 h-3" />
                      <span>Évaluer</span>
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* EDIT COMPLIANCE DIALOG */}
      {selectedControl && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#1E293B] w-full max-w-md rounded-xl border border-slate-200 dark:border-slate-800 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/60 pb-3">
              <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-blue-500" />
                <span>Évaluation de conformité</span>
              </h4>
              <button 
                onClick={() => setSelectedControl(null)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4.5 h-4.5" />
              </button>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] font-mono font-bold text-slate-400">
                {selectedControl.standard} &bull; {selectedControl.section}
              </span>
              <h5 className="font-bold text-xs text-slate-800 dark:text-slate-200 font-sans">
                {selectedControl.control_name}
              </h5>
            </div>

            <form onSubmit={handleUpdate} className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Statut d'évaluation</label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value as any)}
                  className="w-full px-3 py-2.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer font-mono"
                >
                  <option value="COMPLIANT">Compliant (Conforme)</option>
                  <option value="PARTIAL">Partial (Partiel)</option>
                  <option value="NON_COMPLIANT">Non Compliant (Non conforme)</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Évidence d'audit / Preuve technique</label>
                <textarea
                  required
                  placeholder="Justifiez la conformité avec des faits ou des configurations SIEM réelles..."
                  value={newEvidence}
                  onChange={(e) => setNewEvidence(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 h-28 resize-none font-sans leading-relaxed"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-100 dark:border-slate-800/60">
                <button
                  type="button"
                  onClick={() => setSelectedControl(null)}
                  className="px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900 transition-all cursor-pointer"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer shadow-md"
                >
                  Enregistrer l'évaluation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
