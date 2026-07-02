import { BaseService } from "./baseService";
import { mapPlaybook } from "./mappers";
import type { Playbook, UserRole } from "../types";

export class PlaybookService extends BaseService {
  async getPlaybooks(): Promise<Playbook[]> {
    const res = await this.request<Record<string, unknown>[]>("GET", "/playbooks");
    return (Array.isArray(res) ? res : []).map(mapPlaybook);
  }

  async getPlaybookById(id: string): Promise<Playbook> {
    const row = await this.request<Record<string, unknown>>("GET", `/playbooks/${id}`);
    return mapPlaybook(row);
  }

  async triggerPlaybook(
    id: string,
    user: string,
    role: UserRole,
  ): Promise<Playbook> {
    const row = await this.request<Record<string, unknown>>(
      "POST",
      `/playbooks/${id}/trigger`,
      { user, role },
    );
    return mapPlaybook(row);
  }
}
