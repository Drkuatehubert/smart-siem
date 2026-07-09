import { type UserRole } from "../types";

export type ModuleID =
  | "dashboard"
  | "alerts"
  | "incidents"
  | "logs"
  | "ueba"
  | "rules"
  | "threat_intel"
  | "agents"
  | "vuln"
  | "playbooks"
  | "reports"
  | "compliance"
  | "admin";

export interface ModuleConfig {
  id: ModuleID;
  label: string;
  category: "Operational" | "Intelligence" | "Governance" | "System";
}

export const SIEM_MODULES: ModuleConfig[] = [
  { id: "dashboard", label: "Tableau de bord", category: "Operational" },
  { id: "alerts", label: "Alertes de Sécurité", category: "Operational" },
  { id: "incidents", label: "Gestion des Incidents", category: "Operational" },
  { id: "logs", label: "Analyseur de Logs", category: "Operational" },
  { id: "ueba", label: "UEBA (Anomalies)", category: "Operational" },
  { id: "rules", label: "Moteur de Règles", category: "Intelligence" },
  {
    id: "threat_intel",
    label: "Threat Intelligence",
    category: "Intelligence",
  },
  { id: "agents", label: "Agents & Collecteurs", category: "Intelligence" },
  { id: "vuln", label: "Gestion des Vulnérabilités", category: "Intelligence" },
  { id: "playbooks", label: "SOAR Orchestration", category: "Governance" },
  { id: "reports", label: "Rapports & Audit", category: "Governance" },
  {
    id: "compliance",
    label: "Gouvernance & Conformité",
    category: "Governance",
  },
  { id: "admin", label: "Administration & RBAC", category: "System" },
];

export interface RolePermissions {
  canEditVuln: boolean;
  canEditThreatIntel: boolean;
  canEditCompliance: boolean;
  canTriggerPlaybook: boolean;
  canEditRules: boolean;
  canEditIncidents: boolean;
  canManageUsers: boolean;
  canEditAlerts: boolean;
  allowedModules: ModuleID[];
}

export const RBAC_POLICIES: Record<UserRole, RolePermissions> = {
  admin: {
    allowedModules: [
      "dashboard",
      "alerts",
      "incidents",
      "logs",
      "ueba",
      "rules",
      "threat_intel",
      "agents",
      "vuln",
      "playbooks",
      "reports",
      "compliance",
      "admin",
    ],
    canEditVuln: true,
    canEditThreatIntel: true,
    canEditCompliance: true,
    canTriggerPlaybook: true,
    canEditRules: true,
    canEditIncidents: true,
    canManageUsers: true,
    canEditAlerts: true,
  },
  analyst: {
    allowedModules: [
      "dashboard",
      "alerts",
      "incidents",
      "logs",
      "ueba",
      "rules",
      "threat_intel",
      "agents",
      "vuln",
      "playbooks",
      "reports",
      "compliance",
    ],
    canEditVuln: true,
    canEditThreatIntel: true,
    canEditCompliance: false,
    canTriggerPlaybook: true,
    canEditRules: false,
    canEditIncidents: true,
    canManageUsers: false,
    canEditAlerts: true,
  },
  rssi: {
    allowedModules: [
      "dashboard",
      "alerts",
      "incidents",
      "logs",
      "ueba",
      "rules",
      "threat_intel",
      "agents",
      "vuln",
      "playbooks",
      "reports",
      "compliance",
    ],
    canEditVuln: false,
    canEditThreatIntel: false,
    canEditCompliance: true,
    canTriggerPlaybook: false,
    canEditRules: false,
    canEditIncidents: false,
    canManageUsers: false,
    canEditAlerts: false,
  },
  auditor: {
    allowedModules: [
      "dashboard",
      "alerts",
      "incidents",
      "logs",
      "vuln",
      "reports",
      "compliance",
    ],
    canEditVuln: false,
    canEditThreatIntel: false,
    canEditCompliance: false,
    canTriggerPlaybook: false,
    canEditRules: false,
    canEditIncidents: false,
    canManageUsers: false,
    canEditAlerts: false,
  },
  reader: {
    allowedModules: [
      "dashboard",
      "alerts",
      "incidents",
      "logs",
      "ueba",
      "threat_intel",
      "vuln",
      "reports",
      "compliance",
    ],
    canEditVuln: false,
    canEditThreatIntel: false,
    canEditCompliance: false,
    canTriggerPlaybook: false,
    canEditRules: false,
    canEditIncidents: false,
    canManageUsers: false,
    canEditAlerts: false,
  },
};

// FIX: Added safe default and validation
export function isModuleAllowed(role: UserRole | undefined | null, moduleId: ModuleID): boolean {
  // Check if role exists and is valid
  if (!role) {
    console.warn(`isModuleAllowed called with undefined role for module: ${moduleId}`);
    return false;
  }
  
  // Check if role exists in policies
  const policy = RBAC_POLICIES[role];
  if (!policy) {
    console.warn(`No RBAC policy found for role: ${role}`);
    return false;
  }
  
  // Check if allowedModules exists and includes the module
  return policy.allowedModules?.includes(moduleId) ?? false;
}

export function getRoleBadgeStyles(role: UserRole) {
  switch (role) {
    case "admin":
      return {
        bg: "bg-red-500/10",
        text: "text-red-600 dark:text-red-400",
        border: "border-red-200",
      };
    case "analyst":
      return {
        bg: "bg-emerald-500/10",
        text: "text-emerald-600 dark:text-emerald-400",
        border: "border-emerald-200",
      };
    case "rssi":
      return {
        bg: "bg-purple-500/10",
        text: "text-purple-600 dark:text-purple-400",
        border: "border-purple-200",
      };
    case "auditor":
      return {
        bg: "bg-amber-500/10",
        text: "text-amber-600 dark:text-amber-400",
        border: "border-amber-200",
      };
    case "reader":
    default:
      return {
        bg: "bg-blue-500/10",
        text: "text-blue-600 dark:text-blue-400",
        border: "border-blue-200",
      };
  }
}