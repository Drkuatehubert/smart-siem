import { BaseService } from "./baseService";
import { mapIncident } from "./mappers";
import type { Incident, UserRole } from "../types";

export class IncidentService extends BaseService {
  async getIncidents(): Promise<Incident[]> {
    const res = await this.request<Record<string, unknown>[]>("GET", "/incidents");
    return (Array.isArray(res) ? res : []).map(mapIncident);
  }

  async getIncidentById(id: string): Promise<Incident> {
    const row = await this.request<Record<string, unknown>>("GET", `/incidents/${id}`);
    return mapIncident(row);
  }

  async createIncident(
    alertId: string,
    title: string,
    severity: Incident["severity"],
    user: string,
    role: UserRole,
  ): Promise<Incident> {
    const row = await this.request<Record<string, unknown>>("POST", "/incidents", {
      alert_id: alertId,
      titre: title,
      priorite: severity,
      user,
      role,
    });
    return mapIncident(row);
  }

  async updateIncidentStatus(
    id: string,
    status: Incident["status"],
    user: string,
    role: UserRole,
  ): Promise<Incident> {
    const row = await this.request<Record<string, unknown>>(
      "PATCH",
      `/incidents/${id}/status`,
      { status, user, role },
    );
    return mapIncident(row);
  }

  async assignIncident(
    id: string,
    assignee: string,
    user: string,
    role: UserRole,
  ): Promise<Incident> {
    const row = await this.request<Record<string, unknown>>(
      "PATCH",
      `/incidents/${id}/assign`,
      { assigned_to: assignee, user, role },
    );
    return mapIncident(row);
  }

  async addResponseAction(
    id: string,
    action: string,
    target: string,
    by: string,
  ): Promise<Incident> {
    const row = await this.request<Record<string, unknown>>(
      "POST",
      `/incidents/${id}/actions`,
      { action, target, by },
    );
    return mapIncident(row);
  }
}
