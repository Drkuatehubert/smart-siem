// src/Services/incidentService.ts
import { BaseService } from './baseService';
import type { Incident, UserRole } from '../types';

// Mock data
const MOCK_INCIDENTS: Incident[] = [
  {
    id: 'inc-101',
    title: 'Brute Force SSH sur Serveur Web srv-prod-web-01',
    description: 'Plus de 150 tentatives d\'authentification échouées en moins de 3 minutes depuis l\'IP externe 185.220.101.5.',
    severity: 'HIGH',
    status: 'INVESTIGATING',
    assignee: 'Jean Dupont (SOC)',
    created_at: '2026-06-27T19:06:12Z',
    updated_at: '2026-06-27T19:15:00Z',
    category: 'Brute Force',
    logs_count: 57,
    comments: [
      {
        id: 'c1',
        user: 'Jean Dupont',
        role: 'SOC_ANALYST',
        text: 'IP identifiée comme noeud de sortie Tor.',
        timestamp: '2026-06-27T19:10:00Z'
      }
    ]
  },
  {
    id: 'inc-102',
    title: 'Exfiltration massive de données sur srv-file-share',
    description: 'Détection d\'une anomalie de transfert de données : 14.5 Go de données d\'ingénierie transférés.',
    severity: 'CRITICAL',
    status: 'NEW',
    assignee: 'Non assigné',
    created_at: '2026-06-27T19:10:02Z',
    updated_at: '2026-06-27T19:10:02Z',
    category: 'Data Leak',
    logs_count: 142,
    comments: []
  },
  {
    id: 'inc-103',
    title: 'Campagne de Phishing Microsoft active',
    description: 'Clic sur un lien d\'email redirigeant vers un faux portail de connexion Microsoft 365.',
    severity: 'MEDIUM',
    status: 'NEW',
    assignee: 'Sophie Bernard (SOC)',
    created_at: '2026-06-27T19:11:30Z',
    updated_at: '2026-06-27T19:12:00Z',
    category: 'Phishing',
    logs_count: 4,
    comments: []
  },
  {
    id: 'inc-104',
    title: 'Infection CobaltStrike suspectée',
    description: 'Alerte EDR : détection d\'un binaire CobaltStrike injecté dans PowerShell.',
    severity: 'CRITICAL',
    status: 'MITIGATED',
    assignee: 'Jean Dupont (SOC)',
    created_at: '2026-06-27T19:14:22Z',
    updated_at: '2026-06-27T19:18:00Z',
    category: 'Malware Infection',
    logs_count: 89,
    comments: []
  }
];

export class IncidentService extends BaseService {
  private incidents = [...MOCK_INCIDENTS];
  private auditLogs: any[] = [];

  async getIncidents(): Promise<Incident[]> {
    return this.request('GET', '/incidents', null, () => this.incidents);
  }

  async getIncidentById(id: string): Promise<Incident> {
    return this.request(
      'GET',
      `/incidents/${id}`,
      null,
      () => {
        const found = this.incidents.find(i => i.id === id);
        if (!found) throw new Error(`Incident ${id} non trouvé`);
        return found;
      }
    );
  }

  async createIncident(incident: Omit<Incident, 'id' | 'created_at' | 'updated_at' | 'comments' | 'logs_count'>): Promise<Incident> {
    return this.request(
      'POST',
      '/incidents',
      incident,
      () => {
        const newInc: Incident = {
          ...incident,
          id: `inc-${Date.now()}`,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          logs_count: Math.floor(Math.random() * 50) + 1,
          comments: []
        };
        this.incidents = [newInc, ...this.incidents];
        return newInc;
      }
    );
  }

  async updateIncidentStatus(id: string, status: Incident['status'], user: string, role: UserRole): Promise<Incident> {
    return this.request(
      'PATCH',
      `/incidents/${id}/status`,
      { status, user, role },
      () => {
        this.incidents = this.incidents.map((inc) => {
          if (inc.id === id) {
            return { ...inc, status, updated_at: new Date().toISOString() };
          }
          return inc;
        });
        const updatedInc = this.incidents.find((inc) => inc.id === id);
        if (!updatedInc) throw new Error('Incident non trouvé');
        this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'UPDATE_INCIDENT_STATUS', `Status changed to ${status} for ${id}`, 'SUCCESS');
        return updatedInc;
      }
    );
  }

  async addIncidentComment(id: string, text: string, user: string, role: UserRole): Promise<Incident> {
    return this.request(
      'POST',
      `/incidents/${id}/comments`,
      { text, user, role },
      () => {
        this.incidents = this.incidents.map((inc) => {
          if (inc.id === id) {
            const newComment = {
              id: `comment-${Date.now()}`,
              user,
              role,
              text,
              timestamp: new Date().toISOString()
            };
            return {
              ...inc,
              comments: [...inc.comments, newComment],
              updated_at: new Date().toISOString()
            };
          }
          return inc;
        });
        const updatedInc = this.incidents.find((inc) => inc.id === id);
        if (!updatedInc) throw new Error('Incident non trouvé');
        this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'ADD_COMMENT', `Added comment on ${id}`, 'SUCCESS');
        return updatedInc;
      }
    );
  }

  async assignIncident(id: string, assignee: string, user: string, role: UserRole): Promise<Incident> {
    return this.request(
      'PATCH',
      `/incidents/${id}/assign`,
      { assignee, user, role },
      () => {
        this.incidents = this.incidents.map((inc) => {
          if (inc.id === id) {
            return { ...inc, assignee, updated_at: new Date().toISOString() };
          }
          return inc;
        });
        const updatedInc = this.incidents.find((inc) => inc.id === id);
        if (!updatedInc) throw new Error('Incident non trouvé');
        this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'ASSIGN_INCIDENT', `Assigned ${id} to ${assignee}`, 'SUCCESS');
        return updatedInc;
      }
    );
  }
}