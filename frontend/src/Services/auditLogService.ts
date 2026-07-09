import { BaseService } from "./baseService";
import type { AuditLog } from "../types";
import { unwrapResults } from "./mappers";

export interface AuditLogFilters {
  user_id?: string;
  action?: string;
  from_date?: string;
  to_date?: string;
  page?: number;
  size?: number;
}

export class AuditLogService extends BaseService {
  async getAuditLogs(
    filters?: AuditLogFilters,
  ): Promise<{ results: AuditLog[]; total: number }> {
    const params = new URLSearchParams();
    if (filters?.user_id) params.set("user_id", filters.user_id);
    if (filters?.action) params.set("action", filters.action);
    if (filters?.from_date) params.set("from_date", filters.from_date);
    if (filters?.to_date) params.set("to_date", filters.to_date);
    if (filters?.page) params.set("page", String(filters.page));
    if (filters?.size) params.set("size", String(filters.size));

    const qs = params.toString();
    const res = await this.request<
      { results?: AuditLog[]; total?: number } | AuditLog[]
    >("GET", `/audit/logs${qs ? "?" + qs : ""}`);

    if (Array.isArray(res)) return { results: res, total: res.length };
    return {
      results: unwrapResults<AuditLog>(res),
      total: (res as { total?: number }).total ?? 0,
    };
  }
}
