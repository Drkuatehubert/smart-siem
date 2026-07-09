import { BaseService } from "./baseService";

export interface BlockedIp {
  id: string;
  blocked_ip: string;
  firewall: string;
  alert_id: string | null;
  executed_at: string | null;
  metadata: Record<string, unknown>;
}

export interface DisabledAccount {
  id: string;
  username: string;
  domain: string;
  alert_id: string | null;
  executed_at: string | null;
  metadata: Record<string, unknown>;
}

export interface SoarHistoryEntry {
  id: string;
  action: string;
  playbook_name: string;
  target: string;
  status: string;
  alert_id: string | null;
  executed_at: string | null;
}

export class SoarService extends BaseService {
  async getHistory(): Promise<SoarHistoryEntry[]> {
    return this.request<SoarHistoryEntry[]>("GET", "/soar/history");
  }

  async blockIp(ip: string): Promise<{ status: string; ip: string }> {
    return this.request<{ status: string; ip: string }>("POST", "/soar/block-ip", { ip });
  }

  async disableAccount(username: string): Promise<{ status: string; username: string }> {
    return this.request<{ status: string; username: string }>("POST", "/soar/disable-account", { username });
  }

  async getBlockedIps(): Promise<BlockedIp[]> {
    return this.request<BlockedIp[]>("GET", "/soar/blocked-ips");
  }

  async unblockIp(ip: string): Promise<{ status: string; ip: string }> {
    return this.request<{ status: string; ip: string }>("DELETE", `/soar/blocked-ips/${encodeURIComponent(ip)}`);
  }

  async getDisabledAccounts(): Promise<DisabledAccount[]> {
    return this.request<DisabledAccount[]>("GET", "/soar/disabled-accounts");
  }

  async enableAccount(username: string): Promise<{ status: string; username: string }> {
    return this.request<{ status: string; username: string }>("POST", `/soar/disabled-accounts/${encodeURIComponent(username)}/enable`);
  }
}

export const soarService = new SoarService();
