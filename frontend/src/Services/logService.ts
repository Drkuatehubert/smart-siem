import { BaseService } from "./baseService";
import { mapLogEvent, unwrapResults } from "./mappers";
import type { LogEvent, LogSource, RawLog } from "../types";

export class LogService extends BaseService {
  async getLogs(size = 200): Promise<LogEvent[]> {
    const res = await this.request<{ items: LogEvent[]; total: number } | LogEvent[]>(
      "GET",
      `/logs?size=${size}`,
    );
    return unwrapResults<Record<string, unknown>>(res).map(mapLogEvent);
  }

  async getLogById(id: string): Promise<LogEvent> {
    const row = await this.request<Record<string, unknown>>("GET", `/logs/${id}`);
    return mapLogEvent(row);
  }

  async getRawLogs(): Promise<RawLog[]> {
    return this.request<RawLog[]>("GET", "/raw-logs");
  }

  async getLogSources(): Promise<LogSource[]> {
    const res = await this.request<{ results?: LogSource[] } | LogSource[]>(
      "GET",
      "/sources",
    );
    return unwrapResults<LogSource>(res);
  }
}
