/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Clock,
  User,
  MessageSquare,
  Send,
  CheckCircle,
  AlertCircle,
  Briefcase,
  AlertTriangle,
  FileText,
  UserPlus
} from 'lucide-react';
import api from '../../Services/api';
import type { Incident, UserRole } from '../../types';
import { RBAC_POLICIES } from '../../utils/rbac';

interface IncidentsViewProps {
  activeRole: UserRole;
}

export default function IncidentsView({ activeRole }: IncidentsViewProps) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncId, setSelectedIncId] = useState<string | null>(null);
  const [newCommentText, setNewCommentText] = useState('');
  
  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  // Load incidents
  useEffect(() => {
    async function loadIncidents() {
      try {
        const res = await api.getIncidents();
        setIncidents(res);
        if (res.length > 0) {
          setSelectedIncId(res[0].id);
        }
      } catch (err) {
        console.error('Erreur chargement incidents', err);
      } finally {
        setLoading(false);
      }
    }
    loadIncidents();
  }, []);

  const selectedIncident = incidents.find((i) => i.id === selectedIncId);

  // Can this role edit incidents?
  const canEdit = RBAC_POLICIES[activeRole].canEditIncidents;

  // Handle comments
  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncId || !newCommentText.trim()) return;

    try {
      const updated = await api.addIncidentComment(
        selectedIncId,
        newCommentText,
        'Dominique', // simulated current user
        activeRole
      );
      setIncidents((prev) => prev.map((inc) => (inc.id === selectedIncId ? updated : inc)));
      setNewCommentText('');
    } catch (err) {
      console.error('Erreur ajout commentaire', err);
    }
  };

  // Handle status update
  const handleStatusChange = async (newStatus: Incident['status']) => {
    if (!selectedIncId) return;
    try {
      const updated = await api.updateIncidentStatus(selectedIncId, newStatus, 'Dominique', activeRole);
      setIncidents((prev) => prev.map((inc) => (inc.id === selectedIncId ? updated : inc)));
    } catch (err) {
      console.error('Erreur changement statut', err);
    }
  };

  // Handle assignment change
  const handleAssignChange = async (newAssignee: string) => {
    if (!selectedIncId) return;
    try {
      const updated = await api.assignIncident(selectedIncId, newAssignee, 'Dominique', activeRole);
      setIncidents((prev) => prev.map((inc) => (inc.id === selectedIncId ? updated : inc)));
    } catch (err) {
      console.error('Erreur assignation', err);
    }
  };

  if (loading) {
    return (
      <div id="incidents-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  // Filtered incidents
  const filteredIncidents = incidents.filter((inc) => {
    const matchesStatus = statusFilter === 'ALL' || inc.status === statusFilter;
    const matchesSeverity = severityFilter === 'ALL' || inc.severity === severityFilter;
    return matchesStatus && matchesSeverity;
  });

  return (
    <div id="incidents-view" className="h-full flex overflow-hidden">
      
      {/* LEFT PANEL: Incidents list with Search & Filters */}
      <div className="w-80 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0b0f19] flex flex-col shrink-0 h-full">
        
        {/* Filters block */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <h4 className="font-bold text-xs uppercase text-slate-400 dark:text-slate-500 font-mono tracking-wider">
              FILTRER LES INCIDENTS
            </h4>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-[10px] text-slate-400 font-bold font-mono">STATUT</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full mt-1 px-2.5 py-1.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
              >
                <option value="ALL">Tous</option>
                <option value="NEW">Nouveau</option>
                <option value="INVESTIGATING">En Cours</option>
                <option value="MITIGATED">Mitigé</option>
                <option value="CLOSED">Clos</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] text-slate-400 font-bold font-mono">SEVÉRITÉ</label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="w-full mt-1 px-2.5 py-1.5 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
              >
                <option value="ALL">Toutes</option>
                <option value="CRITICAL">Critique</option>
                <option value="HIGH">Haute</option>
                <option value="MEDIUM">Moyenne</option>
                <option value="LOW">Basse</option>
              </select>
            </div>
          </div>
        </div>

        {/* Scrollable list of incidents */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/60">
          {filteredIncidents.length === 0 ? (
            <div className="p-6 text-center text-slate-400 dark:text-slate-500 font-medium text-xs">
              <ShieldAlert className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2" />
              <span>Aucun incident détecté</span>
            </div>
          ) : (
            filteredIncidents.map((inc) => {
              const isSelected = inc.id === selectedIncId;
              const sevColors = 
                inc.severity === 'CRITICAL' ? 'bg-red-500' :
                inc.severity === 'HIGH' ? 'bg-orange-500' :
                inc.severity === 'MEDIUM' ? 'bg-amber-500' :
                'bg-blue-500';

              const statusBadge = 
                inc.status === 'NEW' ? 'text-rose-500 border-rose-500/20 bg-rose-500/5' :
                inc.status === 'INVESTIGATING' ? 'text-amber-500 border-amber-500/20 bg-amber-500/5' :
                inc.status === 'MITIGATED' ? 'text-emerald-500 border-emerald-500/20 bg-emerald-500/5' :
                'text-slate-400 border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/10';

              return (
                <button
                  key={inc.id}
                  onClick={() => setSelectedIncId(inc.id)}
                  className={`w-full text-left p-4 transition-all flex flex-col gap-2 relative border-l-4 border-transparent ${
                    isSelected 
                      ? 'bg-blue-50/40 dark:bg-blue-950/10 border-l-blue-600' 
                      : 'hover:bg-slate-50/50 dark:hover:bg-slate-900/10'
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                      {inc.id}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${statusBadge}`}>
                      {inc.status}
                    </span>
                  </div>

                  <h5 className="font-bold text-xs text-slate-800 dark:text-slate-200 line-clamp-1">
                    {inc.title}
                  </h5>

                  <div className="flex items-center justify-between mt-1 text-[10px] text-slate-400 dark:text-slate-500 font-mono font-semibold">
                    <div className="flex items-center gap-1.5">
                      <span className={`w-2.5 h-2.5 rounded-full ${sevColors}`}></span>
                      <span>Sévérité {inc.severity}</span>
                    </div>
                    <span>{inc.logs_count} logs</span>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>

      {/* RIGHT PANEL: Incident Detail View */}
      <div className="flex-1 bg-slate-50 dark:bg-[#0F172A] flex flex-col h-full overflow-hidden">
        {selectedIncident ? (
          <div className="flex-1 flex flex-col h-full overflow-hidden">
            
            {/* Detail Header */}
            <div className="p-6 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-[#1E293B] shrink-0 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono font-extrabold text-blue-600 dark:text-blue-400">
                    {selectedIncident.id}
                  </span>
                  <span className="px-2.5 py-0.5 rounded-full bg-red-500/10 text-red-500 font-bold text-[10px] uppercase border border-red-500/20 font-mono">
                    {selectedIncident.category}
                  </span>
                </div>

                {/* Edit options if user has permissions */}
                {canEdit ? (
                  <div className="flex items-center gap-3">
                    {/* Status Select */}
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-400" />
                      <select
                        value={selectedIncident.status}
                        onChange={(e) => handleStatusChange(e.target.value as Incident['status'])}
                        className="px-2.5 py-1.5 rounded-lg border text-xs bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none"
                      >
                        <option value="NEW">Nouveau</option>
                        <option value="INVESTIGATING">En Cours</option>
                        <option value="MITIGATED">Mitigé</option>
                        <option value="CLOSED">Clos</option>
                      </select>
                    </div>

                    {/* Assignee Select */}
                    <div className="flex items-center gap-1.5">
                      <UserPlus className="w-3.5 h-3.5 text-slate-400" />
                      <select
                        value={selectedIncident.assignee}
                        onChange={(e) => handleAssignChange(e.target.value)}
                        className="px-2.5 py-1.5 rounded-lg border text-xs bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none"
                      >
                        <option value="Non assigné">Non assigné</option>
                        <option value="Jean Dupont (SOC)">Jean Dupont (SOC)</option>
                        <option value="Sophie Bernard (SOC)">Sophie Bernard (SOC)</option>
                        <option value="Dominique (SOC)">Dominique (SOC)</option>
                      </select>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-4 text-xs font-mono font-bold text-slate-450">
                    <div className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" />
                      <span>Statut: {selectedIncident.status}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <User className="w-3.5 h-3.5" />
                      <span>Assigné: {selectedIncident.assignee}</span>
                    </div>
                  </div>
                )}
              </div>

              <h3 className="text-lg font-bold text-slate-900 dark:text-slate-50 tracking-tight">
                {selectedIncident.title}
              </h3>
            </div>

            {/* Scrollable Contents (Description, Logs info, Comments) */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              
              {/* Description Card */}
              <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
                <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                  <FileText className="w-4 h-4 text-blue-500" />
                  <span>Description de l'incident</span>
                </h4>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-sans">
                  {selectedIncident.description}
                </p>
              </div>

              {/* Logs count and metrics alert */}
              <div className="bg-blue-50/40 dark:bg-blue-950/10 p-4 rounded-xl border border-blue-100 dark:border-blue-900/30 flex items-center justify-between">
                <div className="flex items-center gap-3 text-xs text-blue-700 dark:text-blue-400 font-semibold">
                  <AlertCircle className="w-4.5 h-4.5 shrink-0" />
                  <span>{selectedIncident.logs_count} entrées de logs liées ont été capturées dans l'index du SOC.</span>
                </div>
              </div>

              {/* Comments / Audit Trail */}
              <div className="space-y-4">
                <h4 className="font-bold text-xs uppercase text-slate-400 font-mono flex items-center gap-2">
                  <MessageSquare className="w-4 h-4 text-blue-500" />
                  <span>Commentaires et Actions de Remédiation</span>
                </h4>

                <div className="space-y-3.5">
                  {selectedIncident.comments.length === 0 ? (
                    <p className="text-xs text-slate-400 italic">Aucun commentaire de remédiation saisi pour l'instant.</p>
                  ) : (
                    selectedIncident.comments.map((comment: { id: React.Key | null | undefined; user: string | number | bigint | boolean | React.ReactElement<unknown, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | React.ReactPortal | Promise<string | number | bigint | boolean | React.ReactPortal | React.ReactElement<unknown, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | null | undefined> | null | undefined; role: string | number | bigint | boolean | React.ReactElement<unknown, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | React.ReactPortal | Promise<string | number | bigint | boolean | React.ReactPortal | React.ReactElement<unknown, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | null | undefined> | null | undefined; timestamp: string | number | Date; text: string | number | bigint | boolean | React.ReactElement<unknown, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | React.ReactPortal | Promise<string | number | bigint | boolean | React.ReactPortal | React.ReactElement<unknown, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | null | undefined> | null | undefined; }) => (
                      <div key={comment.id} className="bg-white dark:bg-[#1E293B] p-4 rounded-xl border border-slate-100 dark:border-slate-800/80 shadow-sm space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-slate-800 dark:text-slate-200">{comment.user}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-900 text-slate-500">
                              {comment.role}
                            </span>
                          </div>
                          <span className="text-[10px] font-mono text-slate-400">
                            {new Date(comment.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-xs text-slate-700 dark:text-slate-300 font-sans leading-relaxed">
                          {comment.text}
                        </p>
                      </div>
                    ))
                  )}
                </div>

                {/* Add Comment input form */}
                <form onSubmit={handleAddComment} className="flex gap-2.5 pt-2">
                  <input
                    type="text"
                    placeholder="Saisir un commentaire ou une action d'analyse..."
                    value={newCommentText}
                    onChange={(e) => setNewCommentText(e.target.value)}
                    className="flex-1 px-3.5 py-2.5 rounded-lg border text-xs bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all"
                  />
                  <button
                    type="submit"
                    className="flex items-center justify-center p-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-all shadow-md shrink-0 cursor-pointer"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </form>
              </div>

            </div>

          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-400">
            <ShieldAlert className="w-12 h-12 text-slate-300 dark:text-slate-700 mb-2 animate-bounce" />
            <span>Sélectionnez un incident pour afficher ses informations détaillées</span>
          </div>
        )}
      </div>

    </div>
  );
}
