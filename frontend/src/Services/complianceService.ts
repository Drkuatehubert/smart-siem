// src/Services/complianceService.ts
import { BaseService } from './baseService';
import type { ComplianceControl, UserRole } from '../types';

const MOCK_COMPLIANCE: ComplianceControl[] = [
  {
    id: 'comp-1',
    standard: 'ISO 27001',
    section: 'A.12.6.1 - Gestion des vulnérabilités techniques',
    control_name: 'Correction des vulnérabilités critiques',
    description: 'Des mesures rapides doivent être prises pour identifier et corriger les vulnérabilités.',
    status: 'PARTIAL',
    evidence: 'Scans mensuels de vulnérabilités actifs.',
    last_audit: '2026-06-15T10:00:00Z'
  },
  {
    id: 'comp-2',
    standard: 'RGPD',
    section: 'Article 32 - Sécurité du traitement',
    control_name: 'Contrôle d\'accès et journalisation',
    description: 'Garantir la confidentialité, l\'intégrité et la disponibilité des données.',
    status: 'COMPLIANT',
    evidence: 'Tous les serveurs ont l\'agent d\'audit activé.',
    last_audit: '2026-06-10T14:00:00Z'
  },
  {
    id: 'comp-3',
    standard: 'SOC 2',
    section: 'CC6.3 - Périmètre réseau et pare-feux',
    control_name: 'Gestion des pare-feux',
    description: 'Les points d\'entrée réseau sont restreints et surveillés.',
    status: 'COMPLIANT',
    evidence: 'Les pare-feux rejettent tout le trafic entrant par défaut.',
    last_audit: '2026-06-20T09:00:00Z'
  },
  {
    id: 'comp-4',
    standard: 'ISO 27001',
    section: 'A.12.4.1 - Journalisation des événements',
    control_name: 'Centralisation des journaux',
    description: 'Les journaux d\'événements doivent être produits et conservés.',
    status: 'COMPLIANT',
    evidence: 'Index centralisé avec réplication sur stockage à froid.',
    last_audit: '2026-06-14T11:00:00Z'
  }
];

export class ComplianceService extends BaseService {
  private compliance = [...MOCK_COMPLIANCE];
  private auditLogs: any[] = [];

  async getCompliance(): Promise<ComplianceControl[]> {
    return this.request('GET', '/compliance', null, () => this.compliance);
  }

  async updateComplianceStatus(id: string, status: ComplianceControl['status'], evidence: string, user: string, role: UserRole): Promise<ComplianceControl> {
    return this.request(
      'PATCH',
      `/compliance/${id}/status`,
      { status, evidence, user, role },
      () => {
        this.compliance = this.compliance.map((c) => {
          if (c.id === id) {
            const updated = {
              ...c,
              status,
              evidence,
              last_audit: new Date().toISOString()
            };
            this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'UPDATE_COMPLIANCE', `Updated ${c.section} to ${status}`, 'SUCCESS');
            return updated;
          }
          return c;
        });
        const updatedComp = this.compliance.find((c) => c.id === id);
        if (!updatedComp) throw new Error('Contrôle de conformité non trouvé');
        return updatedComp;
      }
    );
  }
}