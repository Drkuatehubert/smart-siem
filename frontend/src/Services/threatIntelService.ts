import { BaseService } from "./baseService";
import type { ThreatIndicator, UserRole } from "../types";

export class ThreatIntelService extends BaseService {
  async getThreatIntel(): Promise<ThreatIndicator[]> {
    const res = await this.request<ThreatIndicator[]>("GET", "/threat-intel");
    return Array.isArray(res) ? res : [];
  }

  async addThreatIndicator(
    indicator: Omit<ThreatIndicator, "id" | "last_seen">,
    user: string,
    role: UserRole,
  ): Promise<ThreatIndicator> {
    return this.request<ThreatIndicator>("POST", "/threat-intel", {
      indicator,
      user,
      role,
    });
  }
}
