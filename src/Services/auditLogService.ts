// src/Services/auditLogService.ts
import { BaseService } from "./baseService";
import type { AuditLog } from "../types";

const MOCK_AUDIT_LOGS: AuditLog[] = [
  {
    id: "aud-1",
    user_id: "user-1",
    username_snapshot: "j.dupont",
    action: "TRIGGER_PLAYBOOK",
    resource_type: "playbook",
    resource_id: "play-1",
    performed_at: "2026-06-27T19:15:30Z",
    ip_address: "192.168.1.45",
    user_agent: "Mozilla/5.0 Chrome/120",
    result: "success",
    metadata: {
      playbook_name: "EDR Host Isolation",
      execution_mode: "CONFIRM",
    },
  },
  {
    id: "aud-2",
    user_id: "user-2",
    username_snapshot: "p.durand",
    action: "CREATE_FIREWALL_RULE",
    resource_type: "firewall",
    resource_id: "fw-rule-45",
    performed_at: "2026-06-27T19:14:00Z",
    ip_address: "192.168.1.10",
    user_agent: "Mozilla/5.0 Firefox/120",
    result: "success",
    metadata: { rule_name: "Block IP 185.220.101.5 on Edge Router" },
  },
  {
    id: "aud-3",
    user_id: "user-1",
    username_snapshot: "j.dupont",
    action: "UPDATE_INCIDENT_STATUS",
    resource_type: "incident",
    resource_id: "inc-103",
    performed_at: "2026-06-27T19:12:00Z",
    ip_address: "192.168.1.46",
    user_agent: "Mozilla/5.0 Chrome/120",
    result: "success",
    metadata: { old_status: "open", new_status: "in_progress" },
  },
  {
    id: "aud-4",
    user_id: "user-2",
    username_snapshot: "p.durand",
    action: "UPDATE_RBAC_POLICY",
    resource_type: "rbac",
    resource_id: "policy-rssi",
    performed_at: "2026-06-27T18:50:00Z",
    ip_address: "10.0.0.2",
    user_agent: "Mozilla/5.0 Chrome/120",
    result: "success",
    metadata: { change: "Règles de lecture pour le rôle RSSI mises à jour" },
  },
  {
    id: "aud-5",
    user_id: "user-3",
    username_snapshot: "m.lemaire",
    action: "USER_LOGIN_FAILED",
    resource_type: "session",
    resource_id: null,
    performed_at: "2026-06-27T18:45:00Z",
    ip_address: "10.0.0.15",
    user_agent: "Mozilla/5.0 Safari",
    result: "denied",
    metadata: { reason: "MFA code invalide", attempt: 1 },
  },
];

export class AuditLogService extends BaseService {
  private auditLogs = [...MOCK_AUDIT_LOGS];

  async getAuditLogs(): Promise<AuditLog[]> {
    return this.request("GET", "/audit-logs", null, () => this.auditLogs);
  }
}
