import { BaseService } from "./baseService";
import { mapUser, unwrapResults } from "./mappers";
import type { User } from "../types";

export class UserService extends BaseService {
  async getUsers(): Promise<User[]> {
    const res = await this.request<
      { results?: Record<string, unknown>[] } | Record<string, unknown>[]
    >("GET", "/users");
    return unwrapResults<Record<string, unknown>>(res).map(mapUser);
  }

  async getUserById(id: string): Promise<User> {
    const row = await this.request<Record<string, unknown>>("GET", `/users/${id}`);
    return mapUser(row);
  }

  async createUser(user: {
    username: string;
    email: string;
    password: string;
    role: string;
    mfa_enabled?: boolean;
    org_scope?: string;
  }): Promise<User> {
    const row = await this.request<Record<string, unknown>>("POST", "/users", user);
    return mapUser(row);
  }

  async updateRole(id: string, role: string): Promise<User> {
    const row = await this.request<Record<string, unknown>>(
      "PATCH",
      `/users/${id}/role`,
      { role },
    );
    return mapUser(row);
  }

  async disableUser(id: string): Promise<User> {
    const row = await this.request<Record<string, unknown>>(
      "POST",
      `/users/${id}/disable`,
    );
    return mapUser(row);
  }

  async enableUser(id: string): Promise<User> {
    const row = await this.request<Record<string, unknown>>(
      "POST",
      `/users/${id}/enable`,
      { is_active: true },
    );
    return mapUser(row);
  }

  async resetPassword(id: string): Promise<{ temp_password: string }> {
    return this.request<{ temp_password: string }>(
      "POST",
      `/users/${id}/reset-password`,
    );
  }

  async getUserActivity(id: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("GET", `/users/${id}/activity`);
  }

  async lockUser(id: string): Promise<User> {
    return this.disableUser(id);
  }
}
