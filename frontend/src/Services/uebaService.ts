import { BaseService } from "./baseService";
import { mapUebaProfile, unwrapResults } from "./mappers";
import type { UebaProfile } from "../types";

export class UebaService extends BaseService {
  async getProfiles(): Promise<UebaProfile[]> {
    const res = await this.request<unknown>("GET", "/ueba/profiles");
    const rows = unwrapResults<Record<string, unknown>>(res);
    return rows.map(mapUebaProfile);
  }

  async getProfileByEntity(entityId: string): Promise<UebaProfile | undefined> {
    const profiles = await this.getProfiles();
    return profiles.find((p) => p.entity_id === entityId);
  }

  async computeProfiles(): Promise<{ status: string; message?: string }> {
    return this.request("POST", "/ueba/compute");
  }
}
