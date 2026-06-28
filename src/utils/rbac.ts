import { type UserRole } from '../types';

export type ModuleID =
  | 'dashboard' | 'incidents' | 'logs' | 'ueba'
  | 'rules' | 'threat_intel' | 'agents' | 'vuln'
  | 'playbooks' | 'reports' | 'compliance' | 'admin';

export interface ModuleConfig {
  id: ModuleID;
  label: string;
  category: 'Operational' | 'Intelligence' | 'Governance' | 'System';
}

export const SIEM_MODULES: ModuleConfig[] = [
  { id: 'dashboard', label: 'Tableau de bord', category: 'Operational' },
  { id: 'incidents', label: 'Gestion des Incidents', category: 'Operational' },
  { id: 'logs', label: 'Analyseur de Logs', category: 'Operational' },
  { id: 'ueba', label: 'UEBA (Anomalies)', category: 'Operational' },
  { id: 'rules', label: 'Moteur de Règles', category: 'Intelligence' },
  { id: 'threat_intel', label: 'Threat Intelligence', category: 'Intelligence' },
  { id: 'agents', label: 'Agents & Collecteurs', category: 'Intelligence' },
  { id: 'vuln', label: 'Gestion des Vulnérabilités', category: 'Intelligence' },
  { id: 'playbooks', label: 'SOAR Orchestration', category: 'Governance' },
  { id: 'reports', label: 'Rapports & Audit', category: 'Governance' },
  { id: 'compliance', label: 'Gouvernance & Conformité', category: 'Governance' },
  { id: 'admin', label: 'Administration & RBAC', category: 'System' }
];

export interface RolePermissions {
  canEditVuln: any;
  canEditThreatIntel: any;
  canEditCompliance: any;
  canTriggerPlaybook: any;
  canEditRules: any;
  canEditIncidents: any;
  allowedModules: ModuleID[];
}

export const RBAC_POLICIES: Record<UserRole, RolePermissions> = {
  ADMIN: {
      allowedModules: ['dashboard', 'incidents', 'logs', 'ueba', 'rules', 'threat_intel', 'agents', 'vuln', 'playbooks', 'reports', 'compliance', 'admin'],
      canEditVuln: undefined,
      canEditThreatIntel: undefined,
      canEditCompliance: undefined,
      canTriggerPlaybook: undefined,
      canEditRules: undefined,
      canEditIncidents: undefined
  },
  SOC_ANALYST: {
      allowedModules: ['dashboard', 'incidents', 'logs', 'ueba', 'rules', 'threat_intel', 'agents', 'vuln', 'playbooks', 'reports', 'compliance'],
      canEditVuln: undefined,
      canEditThreatIntel: undefined,
      canEditCompliance: undefined,
      canTriggerPlaybook: undefined,
      canEditRules: undefined,
      canEditIncidents: undefined
  },
  RSSI: {
      allowedModules: ['dashboard', 'incidents', 'logs', 'ueba', 'threat_intel', 'vuln', 'reports', 'compliance'],
      canEditVuln: undefined,
      canEditThreatIntel: undefined,
      canEditCompliance: undefined,
      canTriggerPlaybook: undefined,
      canEditRules: undefined,
      canEditIncidents: undefined
  },
  AUDITOR: {
      allowedModules: ['dashboard', 'logs', 'reports', 'compliance'],
      canEditVuln: undefined,
      canEditThreatIntel: undefined,
      canEditCompliance: undefined,
      canTriggerPlaybook: undefined,
      canEditRules: undefined,
      canEditIncidents: undefined
  }
};

export function isModuleAllowed(role: UserRole, moduleId: ModuleID): boolean {
  return RBAC_POLICIES[role].allowedModules.includes(moduleId);
}

export function getRoleBadgeStyles(role: UserRole) {
  switch (role) {
    case 'ADMIN':
      return { bg: 'bg-red-500/10', text: 'text-red-600 dark:text-red-400', border: 'border-red-200' };
    case 'SOC_ANALYST':
      return { bg: 'bg-emerald-500/10', text: 'text-emerald-600 dark:text-emerald-400', border: 'border-emerald-200' };
    case 'RSSI':
      return { bg: 'bg-amber-500/10', text: 'text-amber-600 dark:text-amber-400', border: 'border-amber-200' };
    case 'AUDITOR':
      return { bg: 'bg-blue-500/10', text: 'text-blue-600 dark:text-blue-400', border: 'border-blue-200' };
  }
}