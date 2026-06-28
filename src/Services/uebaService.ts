// src/Services/uebaService.ts
import { BaseService } from './baseService';
import type { UebaAnomaly } from '../types';

const MOCK_ANOMALIES: UebaAnomaly[] = [
  {
    id: 'anom-1',
    user_or_entity: 'j.martin',
    type: 'User',
    risk_score: 92,
    anomaly_description: 'Exfiltration suspecte de 14.5 Go de données vers un serveur inconnu.',
    timestamp: '2026-06-27T19:10:02Z',
    category: 'Data Volume Peak'
  },
  {
    id: 'anom-2',
    user_or_entity: 's.rodriguez',
    type: 'User',
    risk_score: 74,
    anomaly_description: 'Scan de ports rapide initié vers 45 serveurs en moins de 30 secondes.',
    timestamp: '2026-06-27T19:12:05Z',
    category: 'Privilege Escalation'
  },
  {
    id: 'anom-3',
    user_or_entity: 'srv-prod-web-01',
    type: 'Host',
    risk_score: 85,
    anomaly_description: 'Authentification SSH réussie depuis une IP suspecte (Tor exit node).',
    timestamp: '2026-06-27T19:05:00Z',
    category: 'Unusual SSH Country'
  },
  {
    id: 'anom-4',
    user_or_entity: 'h.leclerc (DRH)',
    type: 'User',
    risk_score: 68,
    anomaly_description: 'Connexion VPN réussie depuis Singapour à 02h15 du matin.',
    timestamp: '2026-06-27T02:15:00Z',
    category: 'Suspicious Working Hours'
  }
];

export class UebaService extends BaseService {
  private anomalies = [...MOCK_ANOMALIES];

  async getAnomalies(): Promise<UebaAnomaly[]> {
    return this.request('GET', '/anomalies', null, () => this.anomalies);
  }
}