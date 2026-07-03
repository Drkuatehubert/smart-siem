import { BaseService } from "./baseService";
import { mapUser, unwrapResults } from "./mappers";
import type { User, UserRole } from "../types";

export class UserService extends BaseService {
  async getUsers(): Promise<User[]> {
    const res = await this.request<{ results?: Record<string, unknown>[] } | Record<string, unknown>[]>(
      "GET",
      "/users",
    );
    return unwrapResults<Record<string, unknown>>(res).map(mapUser);
  }

  async getUserById(id: string): Promise<User> {
    const row = await this.request<Record<string, unknown>>("GET", `/users/${id}`);
    return mapUser(row);
  }

  async createUser(
    user: {
      username: string;
      email: string;
      role: UserRole;
      hashed_password: string;
      mfa_secret: string;
      org_scope?: string;
    },
    createdBy: string,
  ): Promise<User> {
    const row = await this.request<Record<string, unknown>>("POST", "/users", {
      ...user,
      created_by: createdBy,
    });
    return mapUser(row);
  }

  async lockUser(
    id: string,
    lockedUntil: string,
    user: string,
    role: UserRole,
  ): Promise<User> {
    const row = await this.request<Record<string, unknown>>(
      "PATCH",
      `/users/${id}/lock`,
      { locked_until: lockedUntil, user, role },
    );
    return mapUser(row);
  }
}
