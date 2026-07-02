// src/Services/reportService.ts
import { BaseService } from './baseService';
import type { SecurityReport, UserRole } from '../types';

const MOCK_REPORTS: SecurityReport[] = [
  {
    id: 'rep-1',
    title: 'Rapport d\'incidents de sécurité - Hebdomadaire S26',
    type: 'WEEKLY',
    generated_by: 'RSSI principal',
    created_at: '2026-06-21T08:00:00Z',
    format: 'PDF',
    size: '1.4 MB'
  },
  {
    id: 'rep-2',
    title: 'Synthèse d\'audit de conformité ISO 27001 - Trimestre 2',
    type: 'COMPLIANCE',
    generated_by: 'Auditeur de Certification',
    created_at: '2026-06-15T12:00:00Z',
    format: 'PDF',
    size: '3.8 MB'
  },
  {
    id: 'rep-3',
    title: 'Journal d\'activité quotidienne SIEM - 26 Juin 2026',
    type: 'DAILY',
    generated_by: 'Génération Automatique',
    created_at: '2026-06-26T23:59:59Z',
    format: 'JSON',
    size: '12 MB'
  }
];

export class ReportService extends BaseService {
  private reports = [...MOCK_REPORTS];
  private auditLogs: any[] = [];

  async getReports(): Promise<SecurityReport[]> {
    return this.request('GET', '/reports', null, () => this.reports);
  }

  async generateReport(title: string, type: SecurityReport['type'], user: string, role: UserRole): Promise<SecurityReport> {
    return this.request(
      'POST',
      '/reports',
      { title, type, user, role },
      () => {
        const newReport: SecurityReport = {
          id: `rep-${Date.now()}`,
          title,
          type,
          generated_by: user,
          created_at: new Date().toISOString(),
          format: 'PDF',
          size: `${(Math.random() * 4 + 0.5).toFixed(1)} MB`
        };
        this.reports = [newReport, ...this.reports];
        this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'GENERATE_REPORT', `Generated security report: ${title}`, 'SUCCESS');
        return newReport;
      }
    );
  }
}