// src/Services/incidentService.ts
import { BaseService } from "./baseService";
import type { Incident, UserRole } from "../types";

const MOCK_INCIDENTS: Incident[] = [
  {
    id: "inc-101",
    alert_id: "alt-101",
    title: "Brute Force SSH sur Serveur Web srv-prod-web-01",
    severity: "high",
    status: "in_progress",
    assigned_to: "user-1",
    opened_at: "2026-06-27T19:06:12Z",
    resolved_at: null,
    response_actions: [
      {
        action: "block_ip",
        target: "185.220.101.5",
        by: "user-1",
        at: "2026-06-27T19:15:00Z",
      },
    ],
    affected_assets: [
      { type: "ip", value: "185.220.101.5" },
      { type: "host", value: "srv-prod-web-01" },
    ],
    root_cause: "Attaque par force brute via noeud de sortie Tor",
    lessons_learned: null,
    ioc_indicators: [{ type: "ip", value: "185.220.101.5" }],
  },
  {
    id: "inc-102",
    alert_id: "alt-102",
    title: "Exfiltration massive de données sur srv-file-share",
    severity: "critical",
    status: "open",
    assigned_to: null,
    opened_at: "2026-06-27T19:10:02Z",
    resolved_at: null,
    response_actions: [],
    affected_assets: [
      { type: "host", value: "srv-file-share" },
      { type: "user_account", value: "j.martin" },
    ],
    root_cause: null,
    lessons_learned: null,
    ioc_indicators: [],
  },
  {
    id: "inc-103",
    alert_id: "alt-103",
    title: "Infection CobaltStrike suspectée",
    severity: "critical",
    status: "in_progress",
    assigned_to: "user-1",
    opened_at: "2026-06-27T19:14:22Z",
    resolved_at: null,
    response_actions: [
      {
        action: "isolate_machine",
        target: "pc-marketing-01",
        by: "user-1",
        at: "2026-06-27T19:18:00Z",
      },
    ],
    affected_assets: [
      { type: "host", value: "pc-marketing-01" },
      { type: "user_account", value: "a.dubois" },
    ],
    root_cause: "Téléchargement de binaire CobaltStrike via PowerShell",
    lessons_learned: "Renforcer la politique d'exécution PowerShell",
    ioc_indicators: [
      { type: "hash", value: "e5f6a7b8c9d0..." },
      { type: "ip", value: "198.51.100.22" },
    ],
  },
];

export class IncidentService extends BaseService {
  private incidents = [...MOCK_INCIDENTS];
  private auditLogs: any[] = [];

  async getIncidents(): Promise<Incident[]> {
    return this.request("GET", "/incidents", null, () => this.incidents);
  }

  async getIncidentById(id: string): Promise<Incident> {
    return this.request("GET", `/incidents/${id}`, null, () => {
      const found = this.incidents.find((i) => i.id === id);
      if (!found) throw new Error(`Incident ${id} non trouvé`);
      return found;
    });
  }

  async createIncident(
    alertId: string,
    title: string,
    severity: Incident["severity"],
    user: string,
    role: UserRole,
  ): Promise<Incident> {
    return this.request(
      "POST",
      "/incidents",
      { alert_id: alertId, title, severity, user, role },
      () => {
        const newInc: Incident = {
          id: `inc-${Date.now()}`,
          alert_id: alertId,
          title,
          severity,
          status: "open",
          assigned_to: null,
          opened_at: new Date().toISOString(),
          resolved_at: null,
          response_actions: [],
          affected_assets: [],
          root_cause: null,
          lessons_learned: null,
          ioc_indicators: [],
        };
        this.incidents = [newInc, ...this.incidents];
        this.auditLogs = this.addAuditLog(
          this.auditLogs,
          user,
          role,
          "CREATE_INCIDENT",
          `Incident created: ${title}`,
          "SUCCESS",
        );
        return newInc;
      },
    );
  }

  async updateIncidentStatus(
    id: string,
    status: Incident["status"],
    user: string,
    role: UserRole,
  ): Promise<Incident> {
    return this.request(
      "PATCH",
      `/incidents/${id}/status`,
      { status, user, role },
      () => {
        this.incidents = this.incidents.map((inc) => {
          if (inc.id === id) {
            return {
              ...inc,
              status,
              resolved_at:
                status === "resolved" || status === "closed"
                  ? new Date().toISOString()
                  : inc.resolved_at,
            };
          }
          return inc;
        });
        const updatedInc = this.incidents.find((inc) => inc.id === id);
        if (!updatedInc) throw new Error("Incident non trouvé");
        this.auditLogs = this.addAuditLog(
          this.auditLogs,
          user,
          role,
          "UPDATE_INCIDENT_STATUS",
          `Status changed to ${status} for ${id}`,
          "SUCCESS",
        );
        return updatedInc;
      },
    );
  }

  async assignIncident(
    id: string,
    assignee: string,
    user: string,
    role: UserRole,
  ): Promise<Incident> {
    return this.request(
      "PATCH",
      `/incidents/${id}/assign`,
      { assigned_to: assignee, user, role },
      () => {
        this.incidents = this.incidents.map((inc) => {
          if (inc.id === id) {
            return { ...inc, assigned_to: assignee };
          }
          return inc;
        });
        const updatedInc = this.incidents.find((inc) => inc.id === id);
        if (!updatedInc) throw new Error("Incident non trouvé");
        this.auditLogs = this.addAuditLog(
          this.auditLogs,
          user,
          role,
          "ASSIGN_INCIDENT",
          `Assigned ${id} to ${assignee}`,
          "SUCCESS",
        );
        return updatedInc;
      },
    );
  }

  async addResponseAction(
    id: string,
    action: string,
    target: string,
    by: string,
  ): Promise<Incident> {
    return this.request(
      "POST",
      `/incidents/${id}/actions`,
      { action, target, by },
      () => {
        this.incidents = this.incidents.map((inc) => {
          if (inc.id === id) {
            return {
              ...inc,
              response_actions: [
                ...inc.response_actions,
                { action, target, by, at: new Date().toISOString() },
              ],
            };
          }
          return inc;
        });
        const updatedInc = this.incidents.find((inc) => inc.id === id);
        if (!updatedInc) throw new Error("Incident non trouvé");
        return updatedInc;
      },
    );
  }
}
