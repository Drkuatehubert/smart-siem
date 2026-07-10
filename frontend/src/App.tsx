/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';

// Security Views Modules
import DashboardView from './components/pages/DashboardView';
import IncidentsView from './components/pages/IncidentsView';
import AlertsView from './components/pages/AlertsView';
import LogsView from './components/pages/LogsView';
import UebaView from './components/pages/UebaView';
import RulesView from './components/pages/RulesView';
import ThreatIntelView from './components/pages/TreatIntelView';
import AgentsView from './components/pages/AgentsView';
import VulnView from './components/pages/VulnView';
import PlaybooksView from './components/pages/PlaybooksView';
import ReportsView from './components/pages/ReportsView';
import ComplianceView from './components/pages/ComplianceView';
import AdminView from './components/pages/AdminView';

// RBAC
import type { UserRole } from './types';
import { type ModuleID, RBAC_POLICIES, isModuleAllowed } from './utils/rbac';
import LoginView from './components/pages/LoginView';

// ─── JWT helpers ─────────────────────────────────────────────────────────────

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
  } catch {
    return null;
  }
}

function isTokenValid(token: string): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== 'number') return false;
  return payload.exp > Date.now() / 1000;
}

function clearAuthStorage(): void {
  ['siem_jwt_token', 'siem_refresh_token', 'siem_authenticated', 'siem_role', 'siem_email', 'siem_username', 'siem_active_module']
    .forEach(k => localStorage.removeItem(k));
}

// ─── App ─────────────────────────────────────────────────────────────────────

export default function App() {
  // Initialisation synchrone basée sur le JWT — évite le flash de redirect
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    const token = localStorage.getItem('siem_jwt_token');
    if (!token) return false;
    if (!isTokenValid(token)) {
      clearAuthStorage();
      return false;
    }
    return true;
  });

  // isLoading reste false (JWT check est synchrone) — gardé pour extensions futures
  const [isLoading] = useState<boolean>(false);

  const [activeModule, setActiveModule] = useState<ModuleID>(() => {
    return (localStorage.getItem('siem_active_module') as ModuleID) || 'dashboard';
  });

  const persistModule = (mod: ModuleID) => {
    localStorage.setItem('siem_active_module', mod);
    setActiveModule(mod);
  };

  const [activeRole, setActiveRole] = useState<UserRole>(() => {
    return (localStorage.getItem('siem_role') as UserRole) || 'reader';
  });

  const [userEmail, setUserEmail] = useState<string>(() => {
    return localStorage.getItem('siem_email') || '';
  });

  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    const saved = localStorage.getItem('siem_theme');
    return saved !== null ? saved === 'dark' : true;
  });

  // Sync theme class on <html>
  useEffect(() => {
    const root = window.document.documentElement;
    if (isDarkMode) {
      root.classList.add('dark');
      root.style.backgroundColor = '#0F172A';
      root.style.setProperty('--bg-primary', '#0F172A');
      root.style.setProperty('--bg-secondary', '#1E293B');
      root.style.setProperty('--text-primary', '#E2E8F0');
    } else {
      root.classList.remove('dark');
      root.style.backgroundColor = '#F1F5F9';
      root.style.removeProperty('--bg-primary');
      root.style.removeProperty('--bg-secondary');
      root.style.removeProperty('--text-primary');
    }
  }, [isDarkMode]);

  // Guard RBAC : redirige vers le premier module autorisé si le rôle change
  useEffect(() => {
    if (!isModuleAllowed(activeRole, activeModule)) {
      const allowed = RBAC_POLICIES[activeRole].allowedModules;
      if (allowed.length > 0) persistModule(allowed[0]);
    }
  }, [activeRole]);

  // Écoute l'événement 401 émis par apiClients.ts
  useEffect(() => {
    const handleUnauthorized = () => handleLogout();
    window.addEventListener('siem:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('siem:unauthorized', handleUnauthorized);
  }, []);

  const toggleTheme = () => {
    setIsDarkMode(prev => {
      const next = !prev;
      localStorage.setItem('siem_theme', next ? 'dark' : 'light');
      return next;
    });
  };

  const handleLoginSuccess = (role: UserRole, email: string, _keepSession?: boolean) => {
    // Toujours persister — le token est déjà dans localStorage via authService.login()
    setIsAuthenticated(true);
    setActiveRole(role);
    setUserEmail(email);
    localStorage.setItem('siem_authenticated', 'true');
    localStorage.setItem('siem_role', role);
    localStorage.setItem('siem_email', email);
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setUserEmail('');
    clearAuthStorage();
  };

  // Spinner pendant la vérification (prévu pour un futur refresh async)
  if (isLoading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-[#0F172A]">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <LoginView
        onLoginSuccess={handleLoginSuccess}
        isDarkMode={isDarkMode}
        toggleTheme={toggleTheme}
      />
    );
  }

  // ── Render view ────────────────────────────────────────────────────────────

  const renderActiveView = () => {
    if (!isModuleAllowed(activeRole, activeModule)) {
      return (
        <div id="rbac-error-boundary" className="p-8 h-full flex flex-col items-center justify-center text-center">
          <div className="w-12 h-12 bg-red-500/10 text-red-500 rounded-full flex items-center justify-center mb-3">
            ⚠️
          </div>
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-50">Accès Refusé</h4>
          <p className="text-xs text-slate-500 mt-1 max-w-xs">Vous ne possédez pas les autorisations nécessaires pour ce module.</p>
        </div>
      );
    }

    switch (activeModule) {
      case 'dashboard':     return <DashboardView setActiveModule={persistModule} />;
      case 'alerts':        return <AlertsView activeRole={activeRole} setActiveModule={persistModule} />;
      case 'incidents':     return <IncidentsView activeRole={activeRole} />;
      case 'logs':          return <LogsView />;
      case 'ueba':          return <UebaView />;
      case 'rules':         return <RulesView activeRole={activeRole} />;
      case 'threat_intel':  return <ThreatIntelView activeRole={activeRole} />;
      case 'agents':        return <AgentsView />;
      case 'vuln':          return <VulnView activeRole={activeRole} />;
      case 'playbooks':     return <PlaybooksView activeRole={activeRole} />;
      case 'reports':       return <ReportsView activeRole={activeRole} />;
      case 'compliance':    return <ComplianceView activeRole={activeRole} />;
      case 'admin':         return <AdminView activeRole={activeRole} />;
      default:              return <DashboardView setActiveModule={persistModule} />;
    }
  };

  const MODULE_METADATA: Record<ModuleID, { title: string; subtitle: string }> = {
    dashboard:   { title: 'Tableau de bord',          subtitle: 'Analyse et métriques globales de sécurité' },
    alerts:      { title: 'Alertes',                  subtitle: 'Détection et triage des alertes de sécurité' },
    incidents:   { title: 'Incidents',                subtitle: 'Gestion et remédiation des incidents actifs' },
    logs:        { title: 'Investigation',             subtitle: 'Analyse de menaces en temps réel' },
    agents:      { title: 'Explorateur de logs',       subtitle: "Télémétrie et collecte d'agents" },
    rules:       { title: 'Règles',                    subtitle: 'Corrélation et logique de détection' },
    playbooks:   { title: 'Playbooks SOAR',            subtitle: 'Automatisation des réponses aux incidents' },
    ueba:        { title: 'UEBA',                      subtitle: 'Détection comportementale et anomalies' },
    reports:     { title: 'Rapports',                  subtitle: "Générateur de synthèses et rapports d'audit" },
    threat_intel:{ title: 'Sources',                   subtitle: 'Threat Intelligence & Flux de menaces' },
    admin:       { title: 'Gestion des utilisateurs',  subtitle: 'Administration système et habilitations RBAC' },
    compliance:  { title: 'Paramètres',                subtitle: 'Configuration globale et réglages du SIEM' },
    vuln:        { title: "Logs d'audit",              subtitle: "Traces d'activité et conformité règlementaire" },
  };

  const currentMeta = MODULE_METADATA[activeModule] || { title: 'Smart SIEM', subtitle: 'Vigilance & Précision' };

  return (
    <div id="siem-app-shell" className="flex h-screen w-screen overflow-hidden bg-[#F1F5F9] dark:bg-[#0F172A] text-slate-900 dark:text-slate-100 transition-colors duration-300 font-sans">
      <Sidebar
        activeModule={activeModule}
        setActiveModule={persistModule}
        activeRole={activeRole}
        onLogout={handleLogout}
      />
      <div id="main-console-area" className="flex-1 flex flex-col h-full overflow-hidden">
        <Header
          isDarkMode={isDarkMode}
          toggleTheme={toggleTheme}
          activeRole={activeRole}
          setActiveRole={setActiveRole}
          title={currentMeta.title}
          subtitle={currentMeta.subtitle}
          setActiveModule={persistModule}
        />
        <main id="console-viewport" className="flex-1 overflow-hidden relative">
          {renderActiveView()}
        </main>
      </div>
    </div>
  );
}
