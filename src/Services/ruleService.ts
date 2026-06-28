// src/Services/ruleService.ts
import { BaseService } from './baseService';
import type { CorrelationRule, UserRole } from '../types';

const MOCK_RULES: CorrelationRule[] = [
  {
    id: 'rule-1',
    name: 'Brute Force SSH Detecté',
    description: 'Déclenche une alerte si plus de 20 tentatives d\'authentification SSH échouent en moins de 120 secondes.',
    query: 'event.type: "auth_fail" AND network.protocol: "ssh" | stats count() by host.name, source.ip | filter count > 20',
    severity: 'HIGH',
    is_active: true,
    category: 'Authentication',
    created_by: 'Administrateur',
    created_at: '2026-01-15T08:00:00Z'
  },
  {
    id: 'rule-2',
    name: 'Exfiltration de Données Anomalie',
    description: 'Alerte en cas de transfert de données supérieur à 5 Go vers une IP externe.',
    query: 'network.bytes_out > 5000000000 AND NOT destination.ip_category: "cloud-approved"',
    severity: 'CRITICAL',
    is_active: true,
    category: 'Data Exfiltration',
    created_by: 'Administrateur',
    created_at: '2026-02-10T10:30:00Z'
  },
  {
    id: 'rule-3',
    name: 'Exécution Suspecte PowerShell',
    description: 'Détection d\'appels de scripts encodés en base64 via PowerShell.',
    query: 'process.name: "powershell.exe" AND (process.args: "-enc" OR process.args: "-EncodedCommand")',
    severity: 'HIGH',
    is_active: true,
    category: 'Execution',
    created_by: 'SOC Analyst',
    created_at: '2026-03-22T14:15:00Z'
  },
  {
    id: 'rule-4',
    name: 'Scan de Ports Interne Rapide',
    description: 'Détecte l\'exploration de ports sur plus de 15 ports différents en 10 secondes.',
    query: 'network.destination_port | stats count_distinct() by source.ip | filter count_distinct > 15',
    severity: 'MEDIUM',
    is_active: false,
    category: 'Reconnaissance',
    created_by: 'SOC Analyst',
    created_at: '2026-04-05T11:45:00Z'
  }
];

export class RuleService extends BaseService {
  private rules = [...MOCK_RULES];
  private auditLogs: any[] = [];

  async getRules(): Promise<CorrelationRule[]> {
    return this.request('GET', '/rules', null, () => this.rules);
  }

  async getRuleById(id: string): Promise<CorrelationRule> {
    return this.request(
      'GET',
      `/rules/${id}`,
      null,
      () => {
        const found = this.rules.find(r => r.id === id);
        if (!found) throw new Error(`Règle ${id} non trouvée`);
        return found;
      }
    );
  }

  async addRule(rule: Omit<CorrelationRule, 'id' | 'created_at'>, user: string, role: UserRole): Promise<CorrelationRule> {
    return this.request(
      'POST',
      '/rules',
      { rule, user, role },
      () => {
        const newRule: CorrelationRule = {
          ...rule,
          id: `rule-${Date.now()}`,
          created_at: new Date().toISOString()
        };
        this.rules = [newRule, ...this.rules];
        this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'CREATE_RULE', `Rule created: ${newRule.name}`, 'SUCCESS');
        return newRule;
      }
    );
  }

  async toggleRule(id: string, user: string, role: UserRole): Promise<CorrelationRule> {
    return this.request(
      'PATCH',
      `/rules/${id}/toggle`,
      { user, role },
      () => {
        this.rules = this.rules.map((rule) => {
          if (rule.id === id) {
            const updated = { ...rule, is_active: !rule.is_active };
            this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'TOGGLE_RULE', `${rule.name} set to ${updated.is_active ? 'Active' : 'Inactive'}`, 'SUCCESS');
            return updated;
          }
          return rule;
        });
        const updatedRule = this.rules.find((rule) => rule.id === id);
        if (!updatedRule) throw new Error('Règle non trouvée');
        return updatedRule;
      }
    );
  }
}