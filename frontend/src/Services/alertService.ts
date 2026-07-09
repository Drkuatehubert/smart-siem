import { BaseService } from "./baseService";
import { mapAlert, unwrapResults } from "./mappers";
import type { Alert, UserRole } from "../types";

export class AlertService extends BaseService {
  async getAlerts(): Promise<Alert[]> {
    const res = await this.request<{ results?: Record<string, unknown>[] } | Record<string, unknown>[]>(
      "GET",
      "/alerts",
    );
    return unwrapResults<Record<string, unknown>>(res).map(mapAlert);
  }

  async getAlertById(id: string): Promise<Alert> {
    const row = await this.request<Record<string, unknown>>("GET", `/alerts/${id}`);
    return mapAlert(row);
  }

  async acknowledgeAlert(id: string, user: string, role: UserRole): Promise<Alert> {
    const row = await this.request<Record<string, unknown>>(
      "PATCH",
      `/alerts/${id}/acknowledge`,
      { user, role },
    );
    return mapAlert(row);
  }

  async updateAlertStatus(
    id: string,
    status: Alert["status"],
    user: string,
    role: UserRole,
  ): Promise<Alert> {
    const row = await this.request<Record<string, unknown>>(
      "PATCH",
      `/alerts/${id}/status`,
      { status, user, role },
    );
    return mapAlert(row);
  }

  async triggerSoar(id: string): Promise<{ status: string; alert_id: string }> {
    return this.request<{ status: string; alert_id: string }>(
      "POST",
      `/alerts/${id}/trigger-soar`,
    );
  }
}
