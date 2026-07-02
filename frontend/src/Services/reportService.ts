import { BaseService } from "./baseService";
import type { SecurityReport, UserRole } from "../types";

export class ReportService extends BaseService {
  async getReports(): Promise<SecurityReport[]> {
    const res = await this.request<SecurityReport[]>("GET", "/reports");
    return Array.isArray(res) ? res : [];
  }

  async generateReport(
    title: string,
    type: SecurityReport["type"],
    user: string,
    role: UserRole,
  ): Promise<SecurityReport> {
    return this.request<SecurityReport>("POST", "/reports/generate", {
      title,
      type,
      user,
      role,
    });
  }
}
