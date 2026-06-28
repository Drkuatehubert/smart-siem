/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  Shield,
  Plus,
  Search,
  CheckCircle2,
  XCircle,
  Clock,
  Code,
  AlertTriangle,
  Lock,
  X
} from 'lucide-react';
import api from '../../Services/api';
import type { CorrelationRule, UserRole } from '../../types';
import { RBAC_POLICIES } from '../../utils/rbac';

interface RulesViewProps {
  activeRole: UserRole;
}

export default function RulesView({ activeRole }: RulesViewProps) {
  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  
  // Create rule form states
  const [showModal, setShowModal] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('MEDIUM');
  const [category, setCategory] = useState('');

  const canEdit = RBAC_POLICIES[activeRole].canEditRules;

  useEffect(() => {
    async function loadRules() {
      try {
        const res = await api.getRules();
        setRules(res);
      } catch (err) {
        console.error('Erreur chargement règles de corrélation', err);
      } finally {
        setLoading(false);
      }
    }
    loadRules();
  }, []);

  const handleToggle = async (id: string) => {
    if (!canEdit) return;
    try {
      const updated = await api.toggleRule(id, 'Dominique', activeRole);
      setRules((prev) => prev.map((r) => (r.id === id ? updated : r)));
    } catch (err) {
      console.error('Erreur bascule statut règle', err);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !query.trim()) return;

    try {
      const newRule = await api.addRule(
        {
          name,
          description,
          query,
          severity,
          is_active: true,
          category: category || 'General',
          created_by: 'Dominique'
        },
        'Dominique',
        activeRole
      );
      setRules((prev) => [newRule, ...prev]);
      setShowModal(false);
      // reset form
      setName('');
      setDescription('');
      setQuery('');
      setSeverity('MEDIUM');
      setCategory('');
    } catch (err) {
      console.error('Erreur création de règle', err);
    }
  };

  if (loading) {
    return (
      <div id="rules-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const filteredRules = rules.filter((rule) => {
    return rule.name.toLowerCase().includes(search.toLowerCase()) || 
           rule.description.toLowerCase().includes(search.toLowerCase()) || 
           rule.category.toLowerCase().includes(search.toLowerCase());
  });

  return (
    <div id="rules-view" className="p-6 space-y-6 overflow-y-auto h-full pb-16 relative">
      
      {/* Search and Action Bar */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Shield className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <span>Moteur de Corrélation & Détection</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Configurez des règles d'alerte en continu sur les flux ElasticSearch indexés par le SIEM.
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

          <button
            onClick={() => setShowModal(true)}
            disabled={!canEdit}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-300 dark:disabled:bg-slate-800 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer disabled:cursor-not-allowed shadow-md hover:shadow-blue-500/20"
          >
            <Plus className="w-4 h-4" />
            <span>Créer une règle</span>
          </button>
        </div>
      </div>

      {/* Rules list */}
      <div className="space-y-4">
        {filteredRules.length === 0 ? (
          <div className="py-16 text-center text-slate-400">
            <Shield className="w-10 h-10 text-slate-300 dark:text-slate-700 mx-auto mb-3 animate-pulse" />
            <span>Aucune règle de corrélation configurée.</span>
          </div>
        ) : (
          filteredRules.map((rule) => {
            const sevColors = 
              rule.severity === 'CRITICAL' ? 'text-red-500 bg-red-500/10 border-red-500/20' :
              rule.severity === 'HIGH' ? 'text-orange-500 bg-orange-500/10 border-orange-500/20' :
              rule.severity === 'MEDIUM' ? 'text-amber-500 bg-amber-500/10 border-amber-500/20' :
              'text-blue-500 bg-blue-500/10 border-blue-500/20';

            return (
              <div 
                key={rule.id} 
                className={`bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm transition-all relative overflow-hidden ${
                  !rule.is_active ? 'opacity-70' : ''
                }`}
              >
                {/* Visual Status strip */}
                <div className={`absolute left-0 inset-y-0 w-1 ${rule.is_active ? 'bg-blue-500' : 'bg-slate-300'}`}></div>

                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                  
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] font-mono font-bold text-slate-400">
                        {rule.id}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border uppercase ${sevColors}`}>
                        {rule.severity}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold border border-slate-100 dark:border-slate-800 text-slate-450 uppercase">
                        {rule.category}
                      </span>
                      <h5 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex-1 min-w-[200px]">
                        {rule.name}
                      </h5>
                    </div>

                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {rule.description}
                    </p>

                    {/* Elasticsearch expression code block */}
                    <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-lg border border-slate-200 dark:border-slate-850 flex items-start gap-2.5 font-mono text-[11px] leading-relaxed">
                      <Code className="w-4 h-4 text-blue-500 mt-0.5 shrink-0" />
                      <pre className="text-slate-700 dark:text-slate-300 overflow-x-auto whitespace-pre-wrap break-all select-all flex-1">
                        {rule.query}
                      </pre>
                    </div>
                  </div>

                  {/* Toggle controls */}
                  <div className="flex flex-row md:flex-col items-center justify-between md:justify-start gap-4 shrink-0 border-t md:border-t-0 border-slate-100 dark:border-slate-800/60 pt-3 md:pt-0">
                    <div className="flex items-center gap-1.5">
                      {rule.is_active ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                      ) : (
                        <XCircle className="w-4 h-4 text-slate-400" />
                      )}
                      <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-450">
                        {rule.is_active ? 'Actif' : 'Désactivé'}
                      </span>
                    </div>

                    {canEdit ? (
                      <button
                        onClick={() => handleToggle(rule.id)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                          rule.is_active 
                            ? 'bg-rose-500/10 text-rose-500 border border-rose-500/20 hover:bg-rose-500 hover:text-white' 
                            : 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 hover:bg-emerald-500 hover:text-white'
                        }`}
                      >
                        {rule.is_active ? 'Désactiver' : 'Activer'}
                      </button>
                    ) : (
                      <div className="flex items-center gap-1 text-[10px] text-slate-400 font-bold uppercase font-mono bg-slate-100 dark:bg-slate-900 px-2 py-1 rounded">
                        <Lock className="w-3 h-3" />
                        <span>Lecture Seule</span>
                      </div>
                    )}
                  </div>

                </div>

                <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800/60 pt-3 mt-4 text-[10px] font-mono text-slate-400">
                  <span>Créé par: {rule.created_by}</span>
                  <div className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    <span>Configuré le: {new Date(rule.created_at).toLocaleDateString()}</span>
                  </div>
                </div>

              </div>
            );
          })
        )}
      </div>

      {/* CREATE RULE MODAL DIALOG */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#1E293B] w-full max-w-lg rounded-xl border border-slate-200 dark:border-slate-800 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/60 pb-3">
              <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Shield className="w-4 h-4 text-blue-500" />
                <span>Nouvelle règle de corrélation</span>
              </h4>
              <button 
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4.5 h-4.5" />
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3">
              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Nom de la règle</label>
                <input
                  type="text"
                  required
                  placeholder="ex: Brute Force SSH détecté"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Description</label>
                <textarea
                  placeholder="Expliquez la logique d'alerte..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 h-20 resize-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Criticité d'alerte</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as any)}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
                  >
                    <option value="LOW">Basse</option>
                    <option value="MEDIUM">Moyenne</option>
                    <option value="HIGH">Haute</option>
                    <option value="CRITICAL">Critique</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Catégorie</label>
                  <input
                    type="text"
                    placeholder="ex: Execution, Access"
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Expression de requête SIEM</label>
                <textarea
                  required
                  placeholder="ex: event.category: 'auth_fail' AND network.port: 22"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 h-24 font-mono resize-none"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-100 dark:border-slate-800/60">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900 transition-all cursor-pointer"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer shadow-md"
                >
                  Enregistrer la règle
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
