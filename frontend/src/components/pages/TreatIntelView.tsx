/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  Globe,
  Plus,
  Search,
  CheckCircle,
  AlertTriangle,
  Clock,
  ExternalLink,
  ShieldAlert,
  Calendar,
  Layers,
  X
} from 'lucide-react';
import api from '../../Services/api';
import type { ThreatIndicator, UserRole } from '../../types';
import { RBAC_POLICIES } from '../../utils/rbac';

interface ThreatIntelViewProps {
  activeRole: UserRole;
}

export default function ThreatIntelView({ activeRole }: ThreatIntelViewProps) {
  const [iocs, setIocs] = useState<ThreatIndicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');

  // Add IOC form states
  const [showModal, setShowModal] = useState(false);
  const [indicator, setIndicator] = useState('');
  const [type, setType] = useState<'IP' | 'DOMAIN' | 'HASH_SHA256'>('IP');
  const [threatType, setThreatType] = useState<'C2 Server' | 'Phishing URL' | 'Ransomware Wallet' | 'Botnet Node' | 'Tor Exit Node'>('C2 Server');
  const [confidence, setConfidence] = useState<number>(90);
  const [source, setSource] = useState('');
  const [reputation, setReputation] = useState<'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN'>('MALICIOUS');

  const canEdit = RBAC_POLICIES[activeRole].canEditThreatIntel;

  useEffect(() => {
    async function loadIocs() {
      try {
        const res = await api.getThreatIntel();
        setIocs(res);
      } catch (err) {
        console.error('Erreur chargement threat intelligence', err);
      } finally {
        setLoading(false);
      }
    }
    loadIocs();
  }, []);

  const handleCreateIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicator.trim()) return;

    try {
      const newIoc = await api.addThreatIndicator(
        {
          indicator,
          type,
          threat_type: threatType,
          confidence,
          source: source || 'Analyste Interne',
          reputation
        },
        'Dominique',
        activeRole
      );
      setIocs((prev) => [newIoc, ...prev]);
      setShowModal(false);
      // Reset form
      setIndicator('');
      setType('IP');
      setThreatType('C2 Server');
      setConfidence(90);
      setSource('');
      setReputation('MALICIOUS');
    } catch (err) {
      console.error("Erreur création d'indicateur de menace", err);
    }
  };

  if (loading) {
    return (
      <div id="threat-intel-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const filteredIocs = iocs.filter((ioc) => {
    const matchesSearch = ioc.indicator.toLowerCase().includes(search.toLowerCase()) || 
                          ioc.threat_type.toLowerCase().includes(search.toLowerCase()) || 
                          ioc.source.toLowerCase().includes(search.toLowerCase());
    const matchesType = typeFilter === 'ALL' || ioc.type === typeFilter;
    return matchesSearch && matchesType;
  });

  return (
    <div id="threat-intel-view" className="p-6 space-y-6 overflow-y-auto h-full pb-16 relative">
      
      {/* Search and Action Bar */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <span>Base d'Indicateurs de Menace (Threat Intelligence)</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Consultez et enrichissez les bases d'IoC (IP, noms de domaine, hash SHA-256) synchronisés en temps réel.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Rechercher IoC..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 w-52 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
            />
          </div>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">Tous les types</option>
            <option value="IP">Adresse IP</option>
            <option value="DOMAIN">Nom de Domaine</option>
            <option value="HASH_SHA256">SHA-256</option>
          </select>

          <button
            onClick={() => setShowModal(true)}
            disabled={!canEdit}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-300 dark:disabled:bg-slate-800 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer disabled:cursor-not-allowed shadow-md hover:shadow-blue-500/20"
          >
            <Plus className="w-4 h-4" />
            <span>Ajouter IoC</span>
          </button>
        </div>
      </div>

      {/* Grid displays */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredIocs.length === 0 ? (
          <div className="col-span-full py-16 text-center text-slate-400">
            <Globe className="w-10 h-10 text-slate-300 dark:text-slate-700 mx-auto mb-3 animate-pulse" />
            <span>Aucun indicateur de menace trouvé.</span>
          </div>
        ) : (
          filteredIocs.map((ioc) => {
            const isMalicious = ioc.reputation === 'MALICIOUS';
            const isSuspicious = ioc.reputation === 'SUSPICIOUS';
            
            const repBadge = isMalicious
              ? 'text-red-500 bg-red-500/10 border-red-500/20'
              : isSuspicious
              ? 'text-orange-500 bg-orange-500/10 border-orange-500/20'
              : 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';

            return (
              <div 
                key={ioc.id} 
                className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between gap-4 hover:scale-[1.005] transition-all"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold border border-slate-150 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-450 uppercase">
                      {ioc.type}
                    </span>

                    <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-bold border ${repBadge}`}>
                      {ioc.reputation}
                    </span>
                  </div>

                  {/* Indicator main text */}
                  <div className="space-y-1">
                    <h5 className="font-mono font-bold text-xs text-slate-900 dark:text-slate-100 break-all select-all leading-tight">
                      {ioc.indicator}
                    </h5>
                    <p className="text-[11px] font-sans text-slate-500 dark:text-slate-400 font-semibold">
                      Type de menace: <span className="text-slate-700 dark:text-slate-300">{ioc.threat_type}</span>
                    </p>
                  </div>

                  {/* Confidence Slider indicator */}
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[10px] font-mono font-bold text-slate-400">
                      <span>CONFIDENCE EN L'ALERTE</span>
                      <span className="text-blue-500">{ioc.confidence}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-100 dark:bg-slate-950 rounded-full overflow-hidden">
                      <div 
                        className={`h-full rounded-full ${ioc.confidence >= 80 ? 'bg-red-500' : 'bg-orange-500'}`}
                        style={{ width: `${ioc.confidence}%` }}
                      ></div>
                    </div>
                  </div>
                </div>

                {/* Footer details */}
                <div className="flex flex-col gap-1 border-t border-slate-100 dark:border-slate-800/60 pt-3 text-[10px] font-mono text-slate-400 leading-tight">
                  <div className="flex items-center justify-between">
                    <span>Source: {ioc.source}</span>
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3 h-3" />
                      {new Date(ioc.last_seen).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* ADD IOC MODAL DIALOG */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#1E293B] w-full max-w-lg rounded-xl border border-slate-200 dark:border-slate-800 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/60 pb-3">
              <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-500" />
                <span>Enregistrer un indicateur de compromission</span>
              </h4>
              <button 
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4.5 h-4.5" />
              </button>
            </div>

            <form onSubmit={handleCreateIoc} className="space-y-3">
              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Valeur de l'indicateur</label>
                <input
                  type="text"
                  required
                  placeholder="ex: 185.220.101.5 ou bad-malware-server.ru"
                  value={indicator}
                  onChange={(e) => setIndicator(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Type d'IoC</label>
                  <select
                    value={type}
                    onChange={(e) => setType(e.target.value as any)}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
                  >
                    <option value="IP">Adresse IP</option>
                    <option value="DOMAIN">Nom de Domaine</option>
                    <option value="HASH_SHA256">Hash SHA-256</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Type de menace</label>
                  <select
                    value={threatType}
                    onChange={(e) => setThreatType(e.target.value as any)}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
                  >
                    <option value="C2 Server">Serveur C2 (Command & Control)</option>
                    <option value="Phishing URL">Lien de Phishing</option>
                    <option value="Ransomware Wallet">Adresse Wallet Ransomware</option>
                    <option value="Botnet Node">Hôte de Botnet</option>
                    <option value="Tor Exit Node">Noeud de sortie Tor</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Confiance (%)</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    required
                    value={confidence}
                    onChange={(e) => setConfidence(parseInt(e.target.value))}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none font-mono"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Réputation d'alerte</label>
                  <select
                    value={reputation}
                    onChange={(e) => setReputation(e.target.value as any)}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
                  >
                    <option value="MALICIOUS">Malveillant (Malicious)</option>
                    <option value="SUSPICIOUS">Suspect (Suspicious)</option>
                    <option value="BENIGN">Sain (Benign)</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">Source du renseignement</label>
                <input
                  type="text"
                  placeholder="ex: AlienVault, CrowdStrike Intel"
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500"
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
                  Enregistrer l'IoC
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
