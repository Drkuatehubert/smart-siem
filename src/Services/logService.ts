// src/Services/logService.ts
import { BaseService } from './baseService';
import type { SecurityLog } from '../types';

const MOCK_LOGS: SecurityLog[] = [
  {
    id: 'log-1',
    timestamp: '2026-06-27T19:05:00Z',
    source_ip: '192.168.1.45',
    destination_ip: '10.0.0.12',
    port: 22,
    protocol: 'TCP',
    event_type: 'SSH Login Success',
    severity: 'LOW',
    message: 'SSH login successful for user admin from 192.168.1.45',
    hostname: 'srv-prod-web-01',
    username: 'admin',
    category: 'auth'
  },
  {
    id: 'log-2',
    timestamp: '2026-06-27T19:06:12Z',
    source_ip: '185.220.101.5',
    destination_ip: '10.0.0.12',
    port: 22,
    protocol: 'TCP',
    event_type: 'Authentication Failure',
    severity: 'MEDIUM',
    message: 'SSH connection failed for user root: Invalid credentials',
    hostname: 'srv-prod-web-01',
    username: 'root',
    category: 'auth'
  },
  {
    id: 'log-3',
    timestamp: '2026-06-27T19:07:44Z',
    source_ip: '185.220.101.5',
    destination_ip: '10.0.0.12',
    port: 22,
    protocol: 'TCP',
    event_type: 'Authentication Failure',
    severity: 'HIGH',
    message: 'SSH connection failed for user root (Attempt 45/100)',
    hostname: 'srv-prod-web-01',
    username: 'root',
    category: 'auth'
  },
  {
    id: 'log-4',
    timestamp: '2026-06-27T19:08:15Z',
    source_ip: '10.0.1.104',
    destination_ip: '8.8.8.8',
    port: 53,
    protocol: 'UDP',
    event_type: 'Connection Refused',
    message: 'DNS query block: malicious-malware-c2-domain.com',
    hostname: 'pc-finance-04',
    username: 'm.dupont',
    severity: 'HIGH',
    category: 'dns'
  },
  {
    id: 'log-5',
    timestamp: '2026-06-27T19:10:02Z',
    source_ip: '192.168.1.112',
    destination_ip: '10.0.4.50',
    port: 443,
    protocol: 'HTTPS',
    event_type: 'Data Exfiltration',
    severity: 'CRITICAL',
    message: 'Anomalous volume of data transferred: 14.5 GB uploaded',
    hostname: 'srv-file-share',
    username: 'j.martin',
    category: 'endpoint'
  },
  {
    id: 'log-6',
    timestamp: '2026-06-27T19:11:30Z',
    source_ip: '91.240.118.41',
    destination_ip: '10.0.0.5',
    port: 80,
    protocol: 'HTTP',
    event_type: 'Phishing Click',
    severity: 'HIGH',
    message: 'HTTP redirect to fake-login-microsoft.com',
    hostname: 'pc-hr-02',
    username: 'l.lefevre',
    category: 'network'
  },
  {
    id: 'log-7',
    timestamp: '2026-06-27T19:12:05Z',
    source_ip: '10.0.2.85',
    destination_ip: '10.0.2.254',
    port: 445,
    protocol: 'TCP',
    event_type: 'Port Scan',
    severity: 'MEDIUM',
    message: 'Sequential port probing detected on subnet 10.0.2.0/24',
    hostname: 'pc-dev-08',
    username: 's.rodriguez',
    category: 'network'
  },
  {
    id: 'log-8',
    timestamp: '2026-06-27T19:14:22Z',
    source_ip: '10.0.1.33',
    destination_ip: '198.51.100.22',
    port: 443,
    protocol: 'HTTPS',
    event_type: 'Malware Download',
    severity: 'CRITICAL',
    message: 'Trojan:Win32/CobaltStrike.C downloaded by PowerShell.exe',
    hostname: 'pc-marketing-01',
    username: 'a.dubois',
    category: 'endpoint'
  }
];

export class LogService extends BaseService {
  private logs = [...MOCK_LOGS];

  async getLogs(): Promise<SecurityLog[]> {
    return this.request('GET', '/logs', null, () => this.logs);
  }

  async getLogById(id: string): Promise<SecurityLog> {
    return this.request(
      'GET',
      `/logs/${id}`,
      null,
      () => {
        const found = this.logs.find(l => l.id === id);
        if (!found) throw new Error(`Log ${id} non trouvé`);
        return found;
      }
    );
  }

  async addLog(log: Omit<SecurityLog, 'id' | 'timestamp'>): Promise<SecurityLog> {
    return this.request(
      'POST',
      '/logs',
      log,
      () => {
        const newLog: SecurityLog = {
          ...log,
          id: `log-${Date.now()}`,
          timestamp: new Date().toISOString()
        };
        this.logs = [newLog, ...this.logs];
        return newLog;
      }
    );
  }
}