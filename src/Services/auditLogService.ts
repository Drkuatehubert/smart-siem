// src/Services/auditLogService.ts
import { BaseService } from './baseService';
import type { SystemAuditLog } from '../types';

const MOCK_AUDIT_LOGS: SystemAuditLog[] = [
  {
    id: 'aud-1',
    timestamp: '2026-06-27T19:15:30Z',
    user: 'Jean Dupont',
    role: 'SOC_ANALYST',
    action: 'TRIGGER_PLAYBOOK',
    target: 'EDR Host Isolation sur pc-marketing-01',
    status: 'SUCCESS',
    ip_address: '192.168.1.45'
  },
  {
    id: 'aud-2',
    timestamp: '2026-06-27T19:14:00Z',
    user: 'Pierre Durand',
    role: 'ADMIN',
    action: 'CREATE_FIREWALL_RULE',
    target: 'Block IP 185.220.101.5 on Edge Router',
    status: 'SUCCESS',
    ip_address: '192.168.1.10'
  },
  {
    id: 'aud-3',
    timestamp: '2026-06-27T19:12:00Z',
    user: 'Sophie Bernard',
    role: 'SOC_ANALYST',
    action: 'UPDATE_INCIDENT_STATUS',
    target: 'inc-103 (Campagne de Phishing)',
    status: 'SUCCESS',
    ip_address: '192.168.1.46'
  },
  {
    id: 'aud-4',
    timestamp: '2026-06-27T18:50:00Z',
    user: 'Administrateur Principal',
    role: 'ADMIN',
    action: 'UPDATE_RBAC_POLICY',
    target: 'Règles de lecture pour le rôle RSSI',
    status: 'SUCCESS',
    ip_address: '10.0.0.2'
  }
];

export class AuditLogService extends BaseService {
  private auditLogs = [...MOCK_AUDIT_LOGS];

  async getAuditLogs(): Promise<SystemAuditLog[]> {
    return this.request('GET', '/audit-logs', null, () => this.auditLogs);
  }
}