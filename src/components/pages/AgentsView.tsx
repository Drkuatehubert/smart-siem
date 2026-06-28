/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState} from 'react'
import {
  Server,
  Activity,
  Cpu,
  HardDrive,
  Search,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Clock,
  Database
} from 'lucide-react';
import api from '../../Services/api';
import type { EndpointAgent } from '../../types';

export default function AgentsView() {
  const [agents, setAgents] = useState<EndpointAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  useEffect(() => {
    async function loadAgents() {
      try {
        const res = await api.getAgents();
        setAgents(res);
      } catch (err) {
        console.error('Erreur chargement agents de logs', err);
      } finally {
        setLoading(false);
      }
    }
    loadAgents();
  }, []);

  if (loading) {
    return (
      <div id="agents-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const filteredAgents = agents.filter((ag) => {
    const matchesSearch = ag.hostname.toLowerCase().includes(search.toLowerCase()) || 
                          ag.ip_address.toLowerCase().includes(search.toLowerCase()) ||
                          ag.os.toLowerCase().includes(search.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || ag.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div id="agents-view" className="p-6 space-y-6 overflow-y-auto h-full pb-16">
      
      {/* Search and Filters Header */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Server className="w-4.5 h-4.5 text-blue-600 dark:text-blue-400" />
            <span>Gestion des Agents & Collecteurs</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Surveillez l'état des agents Wazuh, Elastic, Winlogbeat installés sur vos serveurs et postes clients.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Hôte, IP, OS..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 w-52 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">Tous les statuts</option>
            <option value="ONLINE">En ligne</option>
            <option value="OFFLINE">Hors ligne</option>
            <option value="UNSTABLE">Instable</option>
          </select>
        </div>
      </div>

      {/* Agents lists & stats grid */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        
        {/* Left Side: Stats column */}
        <div className="space-y-4">
          
          <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
            <h5 className="font-bold text-xs uppercase text-slate-400 dark:text-slate-500 font-mono tracking-wider">
              Statistiques Globales
            </h5>

            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-500">Total installés</span>
                <span className="font-bold text-slate-800 dark:text-slate-100">{agents.length}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500">Actifs en ligne</span>
                <span className="font-bold text-emerald-500">{agents.filter(a => a.status === 'ONLINE').length}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500">Hors ligne</span>
                <span className="font-bold text-rose-500">{agents.filter(a => a.status === 'OFFLINE').length}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500">Flux instables</span>
                <span className="font-bold text-amber-500">{agents.filter(a => a.status === 'UNSTABLE').length}</span>
              </div>
            </div>
          </div>

          {/* Quick status card on ingestion */}
          <div className="bg-gradient-to-br from-blue-600 to-indigo-700 text-white p-5 rounded-xl shadow-lg shadow-blue-550/10 space-y-3">
            <Database className="w-6 h-6 text-blue-200" />
            <div className="space-y-1">
              <h5 className="text-[10px] font-bold uppercase tracking-wider text-blue-200 font-mono">
                Volume ingéré (24h)
              </h5>
              <p className="text-2xl font-extrabold font-mono">1.28M logs</p>
            </div>
            <p className="text-[10px] text-blue-200 leading-normal">
              Collecteurs d'agents synchronisés avec un taux de perte de paquets de 0.00%.
            </p>
          </div>

        </div>

        {/* Right Side: Scrollable Table of Agents (takes 3 cols) */}
        <div className="xl:col-span-3 bg-white dark:bg-[#1E293B] border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm flex flex-col">
          
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/30 text-[10px] font-bold uppercase text-slate-400 dark:text-slate-500">
                  <th className="py-3 px-5">Hôte (Hostname)</th>
                  <th className="py-3 px-5">Adresse IP</th>
                  <th className="py-3 px-5">Système (OS)</th>
                  <th className="py-3 px-5">Version Agent</th>
                  <th className="py-3 px-5 text-center">Télémétrie CPU/RAM</th>
                  <th className="py-3 px-5 text-right">Logs envoyés</th>
                  <th className="py-3 px-5 text-center">Statut</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-700 dark:text-slate-300">
                {filteredAgents.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-400">
                      <Server className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2" />
                      <span>Aucun agent de logs trouvé.</span>
                    </td>
                  </tr>
                ) : (
                  filteredAgents.map((ag) => {
                    const statusConfig = 
                      ag.status === 'ONLINE' ? { label: 'Online', style: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20' } :
                      ag.status === 'UNSTABLE' ? { label: 'Unstable', style: 'text-amber-500 bg-amber-500/10 border-amber-500/20' } :
                      { label: 'Offline', style: 'text-rose-500 bg-rose-500/10 border-rose-500/20' };

                    return (
                      <tr key={ag.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/10 transition-colors">
                        <td className="py-3 px-5 font-bold text-slate-900 dark:text-slate-100">
                          {ag.hostname}
                        </td>
                        <td className="py-3 px-5 text-slate-500">{ag.ip_address}</td>
                        <td className="py-3 px-5 text-slate-505 dark:text-slate-400 font-sans text-[11px] font-medium">
                          {ag.os}
                        </td>
                        <td className="py-3 px-5 text-slate-400">{ag.version}</td>
                        <td className="py-3 px-5 text-center">
                          {ag.status !== 'OFFLINE' ? (
                            <div className="flex items-center justify-center gap-2.5">
                              <span className="text-[10px] text-slate-400">CPU {ag.cpu_usage}%</span>
                              <span className="text-[10px] text-slate-400">RAM {ag.memory_usage}%</span>
                            </div>
                          ) : (
                            <span className="text-[10px] text-slate-450 italic">-</span>
                          )}
                        </td>
                        <td className="py-3 px-5 text-right font-bold text-slate-650 dark:text-slate-200">
                          {ag.logs_sent.toLocaleString()}
                        </td>
                        <td className="py-3 px-5 text-center">
                          <span className={`px-2 py-0.5 rounded text-[9px] font-bold border uppercase ${statusConfig.style}`}>
                            {statusConfig.label}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

        </div>

      </div>

    </div>
  );
}
