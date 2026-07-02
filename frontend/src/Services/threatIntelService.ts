// src/Services/threatIntelService.ts
import { BaseService } from './baseService';
import type { ThreatIndicator, UserRole } from '../types';

const MOCK_THREAT_INTEL: ThreatIndicator[] = [
  {
    id: 'ioc-1',
    indicator: '185.220.101.5',
    type: 'IP',
    threat_type: 'Tor Exit Node',
    confidence: 95,
    source: 'AbuseIPDB & Tor Project',
    last_seen: '2026-06-27T19:00:00Z',
    reputation: 'MALICIOUS'
  },
  {
    id: 'ioc-2',
    indicator: 'fake-login-microsoft.com',
    type: 'DOMAIN',
    threat_type: 'Phishing URL',
    confidence: 89,
    source: 'PhishTank',
    last_seen: '2026-06-27T18:45:00Z',
    reputation: 'MALICIOUS'
  },
  {
    id: 'ioc-3',
    indicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    type: 'HASH_SHA256',
    threat_type: 'Ransomware Wallet',
    confidence: 100,
    source: 'VirusTotal',
    last_seen: '2026-06-26T12:00:00Z',
    reputation: 'MALICIOUS'
  },
  {
    id: 'ioc-4',
    indicator: '91.240.118.41',
    type: 'IP',
    threat_type: 'C2 Server',
    confidence: 82,
    source: 'AlienVault OTX',
    last_seen: '2026-06-27T19:10:00Z',
    reputation: 'MALICIOUS'
  },
  {
    id: 'ioc-5',
    indicator: 'github-raw-usercontent-mirror.net',
    type: 'DOMAIN',
    threat_type: 'Botnet Node',
    confidence: 65,
    source: 'CrowdStrike Intel',
    last_seen: '2026-06-27T11:30:00Z',
    reputation: 'SUSPICIOUS'
  }
];

export class ThreatIntelService extends BaseService {
  private threatIntel = [...MOCK_THREAT_INTEL];
  private auditLogs: any[] = [];

  async getThreatIntel(): Promise<ThreatIndicator[]> {
    return this.request('GET', '/threat-intel', null, () => this.threatIntel);
  }

  async addThreatIndicator(indicator: Omit<ThreatIndicator, 'id' | 'last_seen'>, user: string, role: UserRole): Promise<ThreatIndicator> {
    return this.request(
      'POST',
      '/threat-intel',
      { indicator, user, role },
      () => {
        const newIndicator: ThreatIndicator = {
          ...indicator,
          id: `ioc-${Date.now()}`,
          last_seen: new Date().toISOString()
        };
        this.threatIntel = [newIndicator, ...this.threatIntel];
        this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'ADD_IOC', `Indicator added: ${newIndicator.indicator}`, 'SUCCESS');
        return newIndicator;
      }
    );
  }
}