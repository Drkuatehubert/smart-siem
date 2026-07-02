import { BaseService } from "./baseService";
import type { ComplianceControl, UserRole } from "../types";

export class ComplianceService extends BaseService {
  async getCompliance(): Promise<ComplianceControl[]> {
    const res = await this.request<ComplianceControl[]>("GET", "/compliance");
    return Array.isArray(res) ? res : [];
  }

  async updateComplianceStatus(
    id: string,
    status: ComplianceControl["status"],
    evidence: string,
    user: string,
    role: UserRole,
  ): Promise<ComplianceControl> {
    return this.request<ComplianceControl>("PATCH", `/compliance/${id}/status`, {
      status,
      evidence,
      user,
      role,
    });
  }
}
