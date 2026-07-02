import { BaseService } from "./baseService";
import { mapUebaProfile } from "./mappers";
import type { UebaProfile } from "../types";

export class UebaService extends BaseService {
  async getProfiles(): Promise<UebaProfile[]> {
    const res = await this.request<Record<string, unknown>[]>("GET", "/ueba/profiles");
    return (Array.isArray(res) ? res : []).map(mapUebaProfile);
  }

  async getProfileByEntity(entityId: string): Promise<UebaProfile | undefined> {
    const profiles = await this.getProfiles();
    return profiles.find((p) => p.entity_id === entityId);
  }
}
