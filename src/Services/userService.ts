// src/Services/userService.ts
import { BaseService } from "./baseService";
import type { User, UserRole } from "../types";

const MOCK_USERS: User[] = [
  {
    id: "user-1",
    username: "j.dupont",
    email: "jean.dupont@smart-siem.com",
    hashed_password: "$2b$12$LJ3m4ys3Lk...",
    role: "analyst",
    mfa_secret: "JBSWY3DPEHPK3PXP",
    mfa_enabled: true,
    org_scope: "SOC",
    is_active: true,
    last_login_at: "2026-06-27T19:00:00Z",
    failed_login_count: 0,
    locked_until: null,
    created_at: "2026-01-15T08:00:00Z",
    created_by: null,
  },
  {
    id: "user-2",
    username: "p.durand",
    email: "pierre.durand@smart-siem.com",
    hashed_password: "$2b$12$X5kL9m2...",
    role: "admin",
    mfa_secret: "K5X2T7M3V4R6...",
    mfa_enabled: true,
    org_scope: null,
    is_active: true,
    last_login_at: "2026-06-27T18:30:00Z",
    failed_login_count: 0,
    locked_until: null,
    created_at: "2026-01-15T08:00:00Z",
    created_by: null,
  },
  {
    id: "user-3",
    username: "m.lemaire",
    email: "marc.lemaire@smart-siem.com",
    hashed_password: "$2b$12$A3fG7hK...",
    role: "admin",
    mfa_secret: "7H9J2L4N6Q8...",
    mfa_enabled: true,
    org_scope: "DSI",
    is_active: true,
    last_login_at: "2026-06-26T09:15:00Z",
    failed_login_count: 1,
    locked_until: null,
    created_at: "2026-02-01T10:00:00Z",
    created_by: "user-2",
  },
  {
    id: "user-4",
    username: "auditeur",
    email: "auditor@smart-siem.com",
    hashed_password: "$2b$12$B8cD0eF...",
    role: "reader",
    mfa_secret: "1A3B5C7D9E...",
    mfa_enabled: true,
    org_scope: "AUDIT",
    is_active: true,
    last_login_at: "2026-06-25T14:00:00Z",
    failed_login_count: 0,
    locked_until: null,
    created_at: "2026-03-01T09:00:00Z",
    created_by: "user-2",
  },
];

export class UserService extends BaseService {
  private users = [...MOCK_USERS];
  private auditLogs: any[] = [];

  async getUsers(): Promise<User[]> {
    return this.request("GET", "/users", null, () => this.users);
  }

  async getUserById(id: string): Promise<User> {
    return this.request("GET", `/users/${id}`, null, () => {
      const found = this.users.find((u) => u.id === id);
      if (!found) throw new Error(`Utilisateur ${id} non trouvé`);
      return found;
    });
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
    return this.request(
      "POST",
      "/users",
      { ...user, created_by: createdBy },
      () => {
        const newUser: User = {
          id: `usr-${Date.now()}`,
          username: user.username,
          email: user.email,
          hashed_password: user.hashed_password,
          role: user.role,
          mfa_secret: user.mfa_secret,
          mfa_enabled: true,
          org_scope: user.org_scope ?? null,
          is_active: true,
          last_login_at: null,
          failed_login_count: 0,
          locked_until: null,
          created_at: new Date().toISOString(),
          created_by: createdBy,
        };
        this.users = [...this.users, newUser];
        this.auditLogs = this.addAuditLog(
          this.auditLogs,
          createdBy,
          "admin",
          "CREATE_USER",
          `Création utilisateur: ${newUser.username}`,
          "SUCCESS",
        );
        return newUser;
      },
    );
  }

  async lockUser(
    id: string,
    lockedUntil: string,
    user: string,
    role: UserRole,
  ): Promise<User> {
    return this.request(
      "PATCH",
      `/users/${id}/lock`,
      { locked_until: lockedUntil, user, role },
      () => {
        this.users = this.users.map((u) => {
          if (u.id === id) {
            return { ...u, locked_until: lockedUntil };
          }
          return u;
        });
        const updated = this.users.find((u) => u.id === id);
        if (!updated) throw new Error("Utilisateur non trouvé");
        this.auditLogs = this.addAuditLog(
          this.auditLogs,
          user,
          role,
          "LOCK_USER",
          `User ${updated.username} locked until ${lockedUntil}`,
          "SUCCESS",
        );
        return updated;
      },
    );
  }
}
