/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Server,
  Terminal,
  RefreshCw,
  Clock,
  Briefcase,
  ListOrdered
} from 'lucide-react';
import api from '../../Services/api';
import type { SOARPlaybook, UserRole } from '../../types';
import { RBAC_POLICIES } from '../../utils/rbac';

interface PlaybooksViewProps {
  activeRole: UserRole;
}

export default function PlaybooksView({ activeRole }: PlaybooksViewProps) {
  const [playbooks, setPlaybooks] = useState<SOARPlaybook[]>([]);
  const [loading, setLoading] = useState(true);
  const [runningPlaybookId, setRunningPlaybookId] = useState<string | null>(null);

  const canTrigger = RBAC_POLICIES[activeRole].canTriggerPlaybook;

  useEffect(() => {
    async function loadPlaybooks() {
      try {
        const res = await api.getPlaybooks();
        setPlaybooks(res);
      } catch (err) {
        console.error('Erreur chargement playbooks SOAR', err);
      } finally {
        setLoading(false);
      }
    }
    loadPlaybooks();
  }, []);

  const handleTrigger = async (id: string) => {
    if (!canTrigger) return;
    setRunningPlaybookId(id);

    try {
      // Simulate orchestration latency
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const updated = await api.triggerPlaybook(id, 'Dominique', activeRole);
      setPlaybooks((prev) => prev.map((p) => (p.id === id ? updated : p)));
    } catch (err) {
      console.error('Erreur exécution playbook', err);
    } finally {
      setRunningPlaybookId(null);
    }
  };

  if (loading) {
    return (
      <div id="playbooks-loading" className="flex-1 flex items-center justify-center p-8 h-full">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div id="playbooks-view" className="p-6 space-y-6 overflow-y-auto h-full pb-16">
      
      {/* Header Description */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Briefcase className="w-4.5 h-4.5 text-blue-600 dark:text-blue-400" />
            <span>Automatisation & Orchestration SOAR (Playbooks)</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Orchestrez et automatisez des réponses aux incidents sur vos infrastructures de manière instantanée et sécurisée.
          </p>
        </div>
      </div>

      {/* Grid displays */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {playbooks.map((play) => {
          const isRunning = runningPlaybookId === play.id;

          return (
            <div 
              key={play.id} 
              className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between gap-5 hover:scale-[1.005] transition-all relative overflow-hidden"
            >
              <div className="space-y-4">
                
                {/* Top header details */}
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                      {play.id}
                    </span>
                    <h5 className="font-bold text-sm text-slate-900 dark:text-slate-100 leading-tight">
                      {play.name}
                    </h5>
                  </div>

                  <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-slate-400">
                    <Clock className="w-3.5 h-3.5" />
                    <span>{play.executions_count} exécutions</span>
                  </div>
                </div>

                <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                  {play.description}
                </p>

                {/* Steps block list */}
                <div className="space-y-2">
                  <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                    <ListOrdered className="w-3.5 h-3.5 text-blue-500" />
                    <span>SÉQUENCE D'ÉTAPES AUTOMATIQUES</span>
                  </div>

                  <div className="space-y-1.5 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                    {play.steps.map((step: string | number | bigint | boolean | React.ReactElement<unknown, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | React.ReactPortal | Promise<string | number | bigint | boolean | React.ReactPortal | React.ReactElement<unknown, string | React.JSXElementConstructor<any>> | Iterable<React.ReactNode> | null | undefined> | null | undefined, idx: React.Key | null | undefined) => (
                      <div key={idx} className="flex items-start gap-2 bg-slate-50 dark:bg-slate-950 p-2 rounded border border-slate-150 dark:border-slate-850">
                        <span className="text-blue-500 font-extrabold w-3">{(Number(idx) || 0) + 1}.</span>
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Trigger description info */}
                <div className="text-[10px] font-mono font-semibold bg-blue-50/20 dark:bg-blue-950/10 p-2 rounded border border-blue-100/30 dark:border-blue-900/10 text-blue-700 dark:text-blue-400">
                  ÉVÉNEMENT DÉCLENCHEUR : {play.trigger_event}
                </div>

              </div>

              {/* Action Trigger line */}
              <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800/60 pt-4 mt-2 font-mono text-[10px] text-slate-400">
                <div>
                  {play.last_triggered ? (
                    <span>Lancé le: {new Date(play.last_triggered).toLocaleString()}</span>
                  ) : (
                    <span className="italic">Jamais déclenché</span>
                  )}
                </div>

                <button
                  onClick={() => handleTrigger(play.id)}
                  disabled={!canTrigger || isRunning}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs font-sans transition-all active:scale-95 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-md hover:shadow-blue-500/20"
                >
                  {isRunning ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Exécution...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Lancer le playbook</span>
                    </>
                  )}
                </button>
              </div>

            </div>
          );
        })}
      </div>

    </div>
  );
}
