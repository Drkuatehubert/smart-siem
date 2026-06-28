/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  Users,
  ShieldAlert,
  Search,
  CheckCircle,
  XCircle,
  Clock,
  Database,
  Calendar,
  Layers,
  Fingerprint,
  Lock,
  LockOpen
} from 'lucide-react';
import api from '../../Services/api';
import type { SystemAuditLog, UserRole } from '../../types';
import { RBAC_POLICIES } from '../../utils/rbac';

interface AdminViewProps {
  activeRole: UserRole;
}

export default function AdminView({ activeRole }: AdminViewProps) {
  const [auditLogs, setAuditLogs] = useState<SystemAuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    async function loadAuditLogs() {
      try {
        const res = await api.getAuditLogs();
        setAuditLogs(res);
      } catch (err) {
        console.error('Erreur chargement logs d\'audit', err);
      } finally {
        setLoading(false);
      }
    }
    loadAuditLogs();
  }, []);

  if (loading) {
    return (
      <div id="admin-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const filteredLogs = auditLogs.filter((log) => {
    return log.user.toLowerCase().includes(search.toLowerCase()) || 
           log.action.toLowerCase().includes(search.toLowerCase()) || 
           log.target.toLowerCase().includes(search.toLowerCase());
  });

  return (
    <div id="admin-view" className="p-6 space-y-6 overflow-y-auto h-full pb-16">
      
      {/* Search Header */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Users className="w-4.5 h-4.5 text-blue-600 dark:text-blue-400" />
            <span>Administration Système & Journal d'Audit RBAC</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Passez en revue les traces d'audit d'activité des analystes et la politique de contrôle d'accès (RBAC) globale.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Rechercher action, cible..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 w-52 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* Grid: Policies breakdown + Audit trail table */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        
        {/* Left column: RBAC Policies Breakdown Matrix */}
        <div className="space-y-4">
          
          <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
            <h5 className="font-bold text-xs uppercase text-slate-400 dark:text-slate-500 font-mono tracking-wider">
              MATRICE DE SÉCURITÉ DES RÔLES (RBAC)
            </h5>

            <div className="space-y-4 text-xs font-mono">
              {Object.entries(RBAC_POLICIES).map(([role, policy]) => {
                const isCurrent = role === activeRole;

                return (
                  <div 
                    key={role} 
                    className={`p-3.5 rounded-lg border transition-all space-y-2.5 ${
                      isCurrent 
                        ? 'border-blue-500/30 bg-blue-50/10 dark:bg-blue-950/5' 
                        : 'border-slate-150 dark:border-slate-850'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900 dark:text-slate-100">
                        {role} {isCurrent && <span className="text-[10px] text-blue-500 font-bold ml-1.5">(Votre Rôle)</span>}
                      </span>
                      <span className="text-[10px] text-slate-400">
                        {policy.allowedModules.length} Modules autorisés
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-1.5 text-[10px] font-semibold text-slate-500 dark:text-slate-400 leading-tight">
                      <div className="flex items-center gap-1">
                        {policy.canEditIncidents ? <LockOpen className="w-3.5 h-3.5 text-emerald-500" /> : <Lock className="w-3.5 h-3.5 text-slate-400" />}
                        <span>Incidents : {policy.canEditIncidents ? 'Écriture' : 'Lecture'}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        {policy.canEditRules ? <LockOpen className="w-3.5 h-3.5 text-emerald-500" /> : <Lock className="w-3.5 h-3.5 text-slate-400" />}
                        <span>Règles : {policy.canEditRules ? 'Écriture' : 'Lecture'}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        {policy.canTriggerPlaybook ? <LockOpen className="w-3.5 h-3.5 text-emerald-500" /> : <Lock className="w-3.5 h-3.5 text-slate-400" />}
                        <span>Playbooks : {policy.canTriggerPlaybook ? 'Exécuter' : 'Bloqué'}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        {policy.canEditCompliance ? <LockOpen className="w-3.5 h-3.5 text-emerald-500" /> : <Lock className="w-3.5 h-3.5 text-slate-400" />}
                        <span>Conformité : {policy.canEditCompliance ? 'Écrit.' : 'Lect.'}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

        </div>

        {/* Right column: Audit logs list table (takes 2 cols) */}
        <div className="xl:col-span-2 bg-white dark:bg-[#1E293B] border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm flex flex-col">
          
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/30 text-[10px] font-bold uppercase text-slate-400 dark:text-slate-500">
                  <th className="py-3.5 px-5">Horodatage</th>
                  <th className="py-3.5 px-5">Utilisateur</th>
                  <th className="py-3.5 px-5 text-center">Rôle</th>
                  <th className="py-3.5 px-5">Action administrative</th>
                  <th className="py-3.5 px-5">Cible (Target ID)</th>
                  <th className="py-3.5 px-5">Adresse IP</th>
                  <th className="py-3.5 px-5 text-center">Résultat</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-700 dark:text-slate-300">
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-400">
                      <Database className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2" />
                      <span>Aucune trace d'audit d'administration trouvée.</span>
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((log) => {
                    return (
                      <tr key={log.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/10 transition-colors">
                        <td className="py-3.5 px-5 text-slate-400">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="py-3.5 px-5 font-bold text-slate-800 dark:text-slate-100 font-sans">
                          {log.user}
                        </td>
                        <td className="py-3.5 px-5 text-center font-bold">
                          <span className="px-1.5 py-0.5 rounded text-[9px] border border-slate-150 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-500 uppercase">
                            {log.role}
                          </span>
                        </td>
                        <td className="py-3.5 px-5 text-blue-600 dark:text-blue-400 font-bold">
                          {log.action}
                        </td>
                        <td className="py-3.5 px-5 max-w-xs truncate text-slate-550 dark:text-slate-300" title={log.target}>
                          {log.target}
                        </td>
                        <td className="py-3.5 px-5 text-slate-400">{log.ip_address}</td>
                        <td className="py-3.5 px-5 text-center">
                          <span className={`px-2 py-0.5 rounded text-[9px] font-bold border uppercase ${
                            log.status === 'SUCCESS' 
                              ? 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20' 
                              : 'text-red-500 bg-red-500/10 border-red-500/20'
                          }`}>
                            {log.status === 'SUCCESS' ? 'Succès' : 'Échec'}
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
