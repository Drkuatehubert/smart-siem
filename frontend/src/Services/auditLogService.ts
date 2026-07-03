import { BaseService } from "./baseService";
import type { AuditLog } from "../types";
import { unwrapResults } from "./mappers";

export class AuditLogService extends BaseService {
  async getAuditLogs(): Promise<AuditLog[]> {
    const res = await this.request<{ results?: AuditLog[] } | AuditLog[]>(
      "GET",
      "/audit/logs",
    );
    return unwrapResults<AuditLog>(res);
  }
}
