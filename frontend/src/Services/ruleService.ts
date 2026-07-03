import { BaseService } from "./baseService";
import { mapRule, unwrapResults } from "./mappers";
import type {
  CorrelationRule,
  UserRole,
  SeverityLevel,
  RuleType,
} from "../types";

export class RuleService extends BaseService {
  async getRules(): Promise<CorrelationRule[]> {
    const res = await this.request<
      { items: Record<string, unknown>[]; total: number } | Record<string, unknown>[]
    >("GET", "/rules");
    return unwrapResults<Record<string, unknown>>(res).map(mapRule);
  }

  async getRuleById(id: string): Promise<CorrelationRule> {
    const row = await this.request<Record<string, unknown>>("GET", `/rules/${id}`);
    return mapRule(row);
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
    const row = await this.request<Record<string, unknown>>("POST", "/rules", {
      nom: rule.name,
      description: rule.description,
      type: rule.rule_type,
      condition: rule.conditions,
      fenetre_temporelle_s: rule.time_window_seconds,
      threshold_count: rule.threshold_count,
      niveau_alerte_genere: rule.alert_level.toUpperCase(),
      confidence_score: rule.confidence_score,
      mitre_tactic: rule.mitre_tactic,
      mitre_technique: rule.mitre_technique,
      active: rule.is_active,
      user,
      role,
    });
    return mapRule(row);
  }

  async toggleRule(
    id: string,
    user: string,
    role: UserRole,
  ): Promise<CorrelationRule> {
    const row = await this.request<Record<string, unknown>>(
      "PATCH",
      `/rules/${id}/toggle`,
      { user, role },
    );
    return mapRule(row);
  }
}
