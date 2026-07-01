// src/Services/ruleService.ts
import { BaseService } from "./baseService";
import type {
  CorrelationRule,
  UserRole,
  SeverityLevel,
  RuleType,
} from "../types";

const MOCK_RULES: CorrelationRule[] = [
  {
    id: "rule-1",
    name: "SSH Brute Force Detection",
    description:
      "Déclenche une alerte si plus de 20 tentatives d'authentification SSH échouent en moins de 120 secondes.",
    rule_type: "threshold",
    conditions: {
      field: "event_action",
      operator: "eq",
      value: "login_failed",
    },
    time_window_seconds: 120,
    threshold_count: 20,
    sources_required: null,
    alert_level: "high",
    confidence_score: 85,
    mitre_tactic: "TA0001",
    mitre_technique: "T1110",
    playbook_id: "play-2",
    is_active: true,
    false_positive_count: 3,
    created_by: "user-1",
  },
  {
    id: "rule-2",
    name: "Data Exfiltration Anomaly",
    description:
      "Alerte en cas de transfert de données supérieur à 5 Go vers une IP externe.",
    rule_type: "threshold",
    conditions: {
      field: "event_action",
      operator: "eq",
      value: "data_exfiltration",
    },
    time_window_seconds: 300,
    threshold_count: 1,
    sources_required: null,
    alert_level: "critical",
    confidence_score: 92,
    mitre_tactic: "TA0010",
    mitre_technique: "T1041",
    playbook_id: null,
    is_active: true,
    false_positive_count: 1,
    created_by: "user-1",
  },
  {
    id: "rule-3",
    name: "Suspicious PowerShell Execution",
    description:
      "Détection d'appels de scripts encodés en base64 via PowerShell.",
    rule_type: "pattern",
    conditions: {
      field: "process_name",
      operator: "eq",
      value: "PowerShell.exe",
    },
    time_window_seconds: null,
    threshold_count: null,
    sources_required: null,
    alert_level: "high",
    confidence_score: 78,
    mitre_tactic: "TA0005",
    mitre_technique: "T1059.001",
    playbook_id: "play-1",
    is_active: true,
    false_positive_count: 5,
    created_by: "user-2",
  },
  {
    id: "rule-4",
    name: "Internal Rapid Port Scan",
    description:
      "Détecte l'exploration de ports sur plus de 15 ports différents en 10 secondes.",
    rule_type: "threshold",
    conditions: {
      field: "event_action",
      operator: "eq",
      value: "port_scan",
    },
    time_window_seconds: 10,
    threshold_count: 15,
    sources_required: null,
    alert_level: "warning",
    confidence_score: 65,
    mitre_tactic: "TA0007",
    mitre_technique: "T1046",
    playbook_id: null,
    is_active: false,
    false_positive_count: 12,
    created_by: "user-2",
  },
];

export class RuleService extends BaseService {
  private rules = [...MOCK_RULES];
  private auditLogs: any[] = [];

  async getRules(): Promise<CorrelationRule[]> {
    return this.request("GET", "/rules", null, () => this.rules);
  }

  async getRuleById(id: string): Promise<CorrelationRule> {
    return this.request("GET", `/rules/${id}`, null, () => {
      const found = this.rules.find((r) => r.id === id);
      if (!found) throw new Error(`Règle ${id} non trouvée`);
      return found;
    });
  }

  async addRule(
    rule: {
      name: string;
      description: string;
      rule_type: RuleType;
      conditions: Record<string, unknown>;
      time_window_seconds?: number;
      threshold_count?: number;
      alert_level: SeverityLevel;
      confidence_score: number;
      mitre_tactic?: string;
      mitre_technique?: string;
      playbook_id?: string;
      is_active: boolean;
    },
    user: string,
    role: UserRole,
  ): Promise<CorrelationRule> {
    return this.request("POST", "/rules", { rule, user, role }, () => {
      const newRule: CorrelationRule = {
        id: `rule-${Date.now()}`,
        name: rule.name,
        description: rule.description,
        rule_type: rule.rule_type,
        conditions: rule.conditions,
        time_window_seconds: rule.time_window_seconds ?? null,
        threshold_count: rule.threshold_count ?? null,
        sources_required: null,
        alert_level: rule.alert_level,
        confidence_score: rule.confidence_score,
        mitre_tactic: rule.mitre_tactic ?? null,
        mitre_technique: rule.mitre_technique ?? null,
        playbook_id: rule.playbook_id ?? null,
        is_active: rule.is_active,
        false_positive_count: 0,
        created_by: user,
      };
      this.rules = [newRule, ...this.rules];
      this.auditLogs = this.addAuditLog(
        this.auditLogs,
        user,
        role,
        "CREATE_RULE",
        `Rule created: ${newRule.name}`,
        "SUCCESS",
      );
      return newRule;
    });
  }

  async toggleRule(
    id: string,
    user: string,
    role: UserRole,
  ): Promise<CorrelationRule> {
    return this.request("PATCH", `/rules/${id}/toggle`, { user, role }, () => {
      this.rules = this.rules.map((rule) => {
        if (rule.id === id) {
          const updated = { ...rule, is_active: !rule.is_active };
          this.auditLogs = this.addAuditLog(
            this.auditLogs,
            user,
            role,
            "TOGGLE_RULE",
            `${rule.name} set to ${updated.is_active ? "Active" : "Inactive"}`,
            "SUCCESS",
          );
          return updated;
        }
        return rule;
      });
      const updatedRule = this.rules.find((rule) => rule.id === id);
      if (!updatedRule) throw new Error("Règle non trouvée");
      return updatedRule;
    });
  }
}
