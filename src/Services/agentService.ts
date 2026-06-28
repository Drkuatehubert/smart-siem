// src/Services/agentService.ts
import { BaseService } from './baseService';
import type { EndpointAgent } from '../types';

const MOCK_AGENTS: EndpointAgent[] = [
  {
    id: 'agent-1',
    hostname: 'srv-prod-web-01',
    ip_address: '10.0.0.12',
    os: 'Ubuntu 22.04',
    version: 'Wazuh v4.7.2',
    status: 'ONLINE',
    last_ping: '2026-06-27T19:18:45Z',
    logs_sent: 145902,
    cpu_usage: 12.5,
    memory_usage: 44.1
  },
  {
    id: 'agent-2',
    hostname: 'srv-file-share',
    ip_address: '10.0.4.50',
    os: 'Windows Server 2022',
    version: 'Winlogbeat v8.11.1',
    status: 'ONLINE',
    last_ping: '2026-06-27T19:18:30Z',
    logs_sent: 890212,
    cpu_usage: 8.2,
    memory_usage: 62.8
  },
  {
    id: 'agent-3',
    hostname: 'pc-marketing-01',
    ip_address: '10.0.1.33',
    os: 'Windows Server 2022',
    version: 'Elastic Agent v8.11.1',
    status: 'ONLINE',
    last_ping: '2026-06-27T19:18:12Z',
    logs_sent: 24501,
    cpu_usage: 2.1,
    memory_usage: 35.6
  },
  {
    id: 'agent-4',
    hostname: 'pc-finance-04',
    ip_address: '10.0.1.104',
    os: 'Windows Server 2022',
    version: 'Wazuh v4.7.2',
    status: 'UNSTABLE',
    last_ping: '2026-06-27T19:10:00Z',
    logs_sent: 11094,
    cpu_usage: 95.0,
    memory_usage: 89.4
  },
  {
    id: 'agent-5',
    hostname: 'pc-ceo-laptop',
    ip_address: '10.0.1.2',
    os: 'macOS Sequoia',
    version: 'Elastic Agent v8.11.1',
    status: 'OFFLINE',
    last_ping: '2026-06-26T18:00:00Z',
    logs_sent: 45012,
    cpu_usage: 0.0,
    memory_usage: 0.0
  }
];

export class AgentService extends BaseService {
  private agents = [...MOCK_AGENTS];

  async getAgents(): Promise<EndpointAgent[]> {
    return this.request('GET', '/agents', null, () => this.agents);
  }

  async getAgentById(id: string): Promise<EndpointAgent> {
    return this.request(
      'GET',
      `/agents/${id}`,
      null,
      () => {
        const found = this.agents.find(a => a.id === id);
        if (!found) throw new Error(`Agent ${id} non trouvé`);
        return found;
      }
    );
  }
}