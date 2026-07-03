import { BaseService } from "./baseService";
import { mapAgent } from "./mappers";
import type { EndpointAgent } from "../types";

export class AgentService extends BaseService {
  async getAgents(): Promise<EndpointAgent[]> {
    const res = await this.request<Record<string, unknown>[]>("GET", "/agents");
    return (Array.isArray(res) ? res : []).map(mapAgent);
  }

  async getAgentById(id: string): Promise<EndpointAgent> {
    const row = await this.request<Record<string, unknown>>("GET", `/agents/${id}`);
    return mapAgent(row);
  }
}
