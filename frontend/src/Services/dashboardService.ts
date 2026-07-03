import { BaseService } from "./baseService";

export interface DashboardSummary {
  total_logs_24h: number;
  total_alerts_open: number;
  critical_alerts: number;
  alerts_by_level: { niveau: string; count: number }[];
  log_volume_by_hour: { hour: string; count: number }[];
}

export class DashboardService extends BaseService {
  async getSummary(): Promise<DashboardSummary> {
    return this.request<DashboardSummary>("GET", "/dashboard/summary");
  }
}
