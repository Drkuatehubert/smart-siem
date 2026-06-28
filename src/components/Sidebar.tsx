import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  FileText,
  UserCheck,
  GitMerge,
  Globe,
  Network,
  Bug,
  Play,
  ClipboardList,
  CheckSquare,
  Settings,
  Lock,
  LogOut,
  Shield
} from 'lucide-react';
import { type ModuleID, isModuleAllowed } from '../utils/rbac';
import type { UserRole } from '../types';

interface SidebarProps {
  activeModule: ModuleID;
  setActiveModule: (module: ModuleID) => void;
  activeRole: UserRole;
  onLogout?: () => void;
}

const ICON_MAP: Record<ModuleID, React.ComponentType<any>> = {
  dashboard: LayoutDashboard,
  incidents: ShieldAlert,
  logs: FileText,
  ueba: UserCheck,
  rules: GitMerge,
  threat_intel: Globe,
  agents: Network,
  vuln: Bug,
  playbooks: Play,
  reports: ClipboardList,
  compliance: CheckSquare,
  admin: Settings
};

export default function Sidebar({ activeModule, setActiveModule, activeRole, onLogout }: SidebarProps) {
  // Flat items and configuration section matching the mockup exactly
  const mainModules = [
    { id: 'dashboard', label: 'Tableau de bord' },
    { id: 'incidents', label: 'Alertes' },
    { id: 'logs', label: 'Investigation' },
    { id: 'agents', label: 'Explorateur de logs' },
    { id: 'rules', label: 'Règles' },
    { id: 'playbooks', label: 'Playbooks SOAR' },
    { id: 'ueba', label: 'UEBA' },
    { id: 'reports', label: 'Rapports' }
  ] as const;

  const configModules = [
    { id: 'threat_intel', label: 'Sources' },
    { id: 'admin', label: 'Gestion des utilisateurs' },
    { id: 'compliance', label: 'Paramètres' },
    { id: 'vuln', label: 'Logs d\'audit' }
  ] as const;

  const handleModuleClick = (moduleId: ModuleID, isAllowed: boolean) => {
    if (isAllowed) {
      setActiveModule(moduleId);
    }
  };

  const renderModuleButton = (id: ModuleID, label: string) => {
    const IconComponent = ICON_MAP[id];
    const isAllowed = isModuleAllowed(activeRole, id);
    const isActive = activeModule === id;

    return (
      <li key={id} id={`nav-item-${id}`}>
        <button
          onClick={() => handleModuleClick(id, isAllowed)}
          className={`w-full flex items-center justify-between px-6 py-2.5 text-xs font-semibold transition-all group relative border-l-4 border-transparent ${
            isActive
              ? 'bg-blue-50 dark:bg-blue-950/20 text-blue-600 dark:text-blue-400 border-l-blue-600 dark:border-l-blue-500 font-bold'
              : isAllowed
              ? 'text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900/40 hover:text-slate-900 dark:hover:text-slate-200'
              : 'text-slate-400 dark:text-slate-600 cursor-not-allowed opacity-50'
          }`}
        >
          <div className="flex items-center gap-3">
            {IconComponent && (
              <IconComponent
                className={`w-4 h-4 shrink-0 transition-colors ${
                  isActive
                    ? 'text-blue-600 dark:text-blue-400'
                    : isAllowed
                    ? 'text-slate-400 dark:text-slate-500 group-hover:text-slate-600 dark:group-hover:text-slate-300'
                    : 'text-slate-300 dark:text-slate-700'
                }`}
              />
            )}
            <span className="truncate">{label}</span>
          </div>

          {!isAllowed && (
            <Lock className="w-3.5 h-3.5 text-slate-300 dark:text-slate-700 shrink-0" />
          )}
        </button>
      </li>
    );
  };

  return (
    <aside id="siem-sidebar" className="w-64 border-r flex flex-col h-screen overflow-y-auto shrink-0 bg-white dark:bg-[#0b0f19] border-slate-200 dark:border-slate-800 transition-colors duration-300">
      {/* Brand logo */}
      <div id="sidebar-logo-container" className="h-16 flex items-center gap-3.5 px-6 border-b border-slate-200 dark:border-slate-800 shrink-0">
        <div className="w-9 h-9 rounded-xl bg-blue-600 dark:bg-blue-600/20 border border-blue-500/20 flex items-center justify-center text-white dark:text-blue-400 shadow-sm shrink-0">
          <Shield className="w-5 h-5" />
        </div>
        <div className="flex flex-col">
          <h1 className="font-bold text-sm tracking-tight text-blue-600 dark:text-blue-400 leading-tight">
            Smart SIEM
          </h1>
          <p className="text-[8px] font-mono font-bold text-slate-400 dark:text-slate-500 tracking-wider uppercase leading-none mt-0.5">
            VIGILANCE & PRÉCISION
          </p>
        </div>
      </div>

      {/* Nav Content */}
      <div id="sidebar-nav-content" className="flex-1 py-4 space-y-5">
        <ul className="space-y-0.5">
          {mainModules.map((m) => renderModuleButton(m.id, m.label))}
        </ul>

        <div className="space-y-2">
          <div className="px-6">
            <h2 className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              CONFIGURATION
            </h2>
          </div>
          <ul className="space-y-0.5">
            {configModules.map((m) => renderModuleButton(m.id, m.label))}
          </ul>
        </div>
      </div>

      {/* Footer Déconnexion and line only, matching mockup perfectly */}
      <div id="sidebar-footer" className="border-t border-slate-200 dark:border-slate-800 shrink-0 p-3">
        {onLogout && (
          <button
            onClick={onLogout}
            id="logout-btn"
            className="w-full flex items-center gap-3 px-6 py-2.5 rounded-lg text-xs font-semibold text-slate-500 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900/40 hover:text-red-600 dark:hover:text-red-400 transition-all text-left group"
          >
            <LogOut className="w-4 h-4 shrink-0 text-slate-400 dark:text-slate-500 group-hover:text-red-500 dark:group-hover:text-red-400" />
            <span>Déconnexion</span>
          </button>
        )}
      </div>
    </aside>
  );
}
