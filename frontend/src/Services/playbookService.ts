// src/Services/playbookService.ts
import { BaseService } from "./baseService";
import type { Playbook, UserRole } from "../types";

const MOCK_PLAYBOOKS: Playbook[] = [
  {
    id: "play-1",
    name: "EDR Host Isolation",
    description: "Isole automatiquement un hôte du réseau via l'agent EDR.",
    action_type: "isolate_machine",
    execution_mode: "CONFIRM",
    parameters: {
      duration_hours: 24,
      notify_email: "soc@smart-siem.com",
    },
    target_type: "machine",
    confirmation_timeout_seconds: 300,
    is_active: true,
    execution_count: 14,
    last_executed_at: "2026-06-27T19:15:30Z",
    created_by: "user-1",
  },
  {
    id: "play-2",
    name: "SSH Brute Force Block",
    description: "Bloque l'IP attaquante au niveau du pare-feu Cloud.",
    action_type: "block_ip",
    execution_mode: "AUTO",
    parameters: {
      duration_hours: 24,
      target_field: "source_ip",
      notify_email: "soc@smart-siem.com",
    },
    target_type: "ip_address",
    confirmation_timeout_seconds: 300,
    is_active: true,
    execution_count: 124,
    last_executed_at: "2026-06-27T19:14:00Z",
    created_by: "user-1",
  },
  {
    id: "play-3",
    name: "Suspicious Domain DNS Block",
    description: "Ajoute un domaine identifié au DNS menteur de l'entreprise.",
    action_type: "block_ip",
    execution_mode: "CONFIRM",
    parameters: {
      duration_hours: 48,
      notify_email: "soc@smart-siem.com",
    },
    target_type: "ip_address",
    confirmation_timeout_seconds: 600,
    is_active: true,
    execution_count: 5,
    last_executed_at: null,
    created_by: "user-2",
  },
];

export class PlaybookService extends BaseService {
  private playbooks = [...MOCK_PLAYBOOKS];
  private auditLogs: any[] = [];

  async getPlaybooks(): Promise<Playbook[]> {
    return this.request("GET", "/playbooks", null, () => this.playbooks);
  }

  async getPlaybookById(id: string): Promise<Playbook> {
    return this.request("GET", `/playbooks/${id}`, null, () => {
      const found = this.playbooks.find((p) => p.id === id);
      if (!found) throw new Error(`Playbook ${id} non trouvé`);
      return found;
    });
  }

  async triggerPlaybook(
    id: string,
    user: string,
    role: UserRole,
  ): Promise<Playbook> {
    return this.request(
      "POST",
      `/playbooks/${id}/trigger`,
      { user, role },
      () => {
        this.playbooks = this.playbooks.map((p) => {
          if (p.id === id) {
            const updated = {
              ...p,
              last_executed_at: new Date().toISOString(),
              execution_count: p.execution_count + 1,
            };
            this.auditLogs = this.addAuditLog(
              this.auditLogs,
              user,
              role,
              "TRIGGER_PLAYBOOK",
              `Triggered SOAR: ${p.name} (mode: ${p.execution_mode})`,
              "SUCCESS",
            );
            return updated;
          }
          return p;
        });
        const updatedPlay = this.playbooks.find((p) => p.id === id);
        if (!updatedPlay) throw new Error("Playbook non trouvé");
        return updatedPlay;
      },
    );
  }
}
