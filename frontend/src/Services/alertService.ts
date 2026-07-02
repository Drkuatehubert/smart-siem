// src/Services/alertService.ts
import { BaseService } from './baseService';
import type { Alert, UserRole } from '../types';

const MOCK_ALERTS: Alert[] = [
  {
    id: 'alt-101',
    rule_id: 'rule-1',
    title: 'Brute Force SSH sur srv-prod-web-01',
    level: 'high',
    status: 'open',
    triggered_at: '2026-06-27T19:06:12Z',
    acknowledged_at: null,
    resolved_at: null,
    acknowledged_by: null,
    correlated_event_ids: ['es-doc-002', 'es-doc-003'],
    source_ips: ['185.220.101.5'],
    affected_hosts: ['srv-prod-web-01'],
    confidence_score: 85,
    mitre_tactic: 'TA0001',
    notes: null
  },
  {
    id: 'alt-102',
    rule_id: 'rule-2',
    title: 'Exfiltration massive de données sur srv-file-share',
    level: 'critical',
    status: 'investigating',
    triggered_at: '2026-06-27T19:10:02Z',
    acknowledged_at: '2026-06-27T19:12:00Z',
    resolved_at: null,
    acknowledged_by: 'user-1',
    correlated_event_ids: ['es-doc-005'],
    source_ips: ['192.168.1.112'],
    affected_hosts: ['srv-file-share'],
    confidence_score: 92,
    mitre_tactic: 'TA0010',
    notes: 'Analyste en cours d\'investigation'
  },
  {
    id: 'alt-103',
    rule_id: 'rule-3',
    title: 'Infection CobaltStrike suspectée',
    level: 'critical',
    status: 'confirmed',
    triggered_at: '2026-06-27T19:14:22Z',
    acknowledged_at: '2026-06-27T19:15:00Z',
    resolved_at: null,
    acknowledged_by: 'user-1',
    correlated_event_ids: ['es-doc-008'],
    source_ips: ['10.0.1.33'],
    affected_hosts: ['pc-marketing-01'],
    confidence_score: 95,
    mitre_tactic: 'TA0005',
    notes: 'CobaltStrike beacon confirmé par EDR'
  }
];

export class AlertService extends BaseService {
  private alerts = [...MOCK_ALERTS];
  private auditLogs: any[] = [];

  async getAlerts(): Promise<Alert[]> {
    return this.request('GET', '/alerts', null, () => this.alerts);
  }

  async getAlertById(id: string): Promise<Alert> {
    return this.request(
      'GET',
      `/alerts/${id}`,
      null,
      () => {
        const found = this.alerts.find(a => a.id === id);
        if (!found) throw new Error(`Alerte ${id} non trouvée`);
        return found;
      }
    );
  }

  async acknowledgeAlert(id: string, user: string, role: UserRole): Promise<Alert> {
    return this.request(
      'PATCH',
      `/alerts/${id}/acknowledge`,
      { user, role },
      () => {
        this.alerts = this.alerts.map((a) => {
          if (a.id === id) {
            return {
              ...a,
              status: 'investigating' as const,
              acknowledged_at: new Date().toISOString(),
              acknowledged_by: user
            };
          }
          return a;
        });
        const updated = this.alerts.find((a) => a.id === id);
        if (!updated) throw new Error('Alerte non trouvée');
        this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'ALERT_ACKNOWLEDGED', `Alert ${id} acknowledged`, 'SUCCESS');
        return updated;
      }
    );
  }

  async updateAlertStatus(id: string, status: Alert['status'], user: string, role: UserRole): Promise<Alert> {
    return this.request(
      'PATCH',
      `/alerts/${id}/status`,
      { status, user, role },
      () => {
        this.alerts = this.alerts.map((a) => {
          if (a.id === id) {
            const updated: Alert = {
              ...a,
              status,
              resolved_at: status === 'false_positive' || status === 'confirmed' ? new Date().toISOString() : a.resolved_at
            };
            return updated;
          }
          return a;
        });
        const updated = this.alerts.find((a) => a.id === id);
        if (!updated) throw new Error('Alerte non trouvée');
        this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'UPDATE_ALERT_STATUS', `Alert ${id} set to ${status}`, 'SUCCESS');
        return updated;
      }
    );
  }
}
