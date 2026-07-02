// src/Services/authService.ts
import { axiosInstance } from './apiClients';
import { BaseService } from "./baseService";
import type { User, UserRole } from "../types";


function toUserRole(role: string): UserRole {
  const map: Record<string, UserRole> = {
    administrateur: "admin",
    admin: "admin",
    analyste: "analyst",
    analyst: "analyst",
    lecteur: "reader",
    reader: "reader",
    auditeur: "reader",
  };
  return map[role.toLowerCase()] ?? "reader";
}

interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  user: {
    user_id: string;
    username: string;
    email?: string;
    role: string;
    org_scope?: string;
    is_active: boolean;
  };
}

export class AuthService extends BaseService {
  async login(
    email: string,
    password?: string,
    _totpCode?: string,
  ): Promise<{ token: string; user: User }> {
    const response = await axiosInstance.post<LoginResponse>("/auth/login", {
      username: email,
      password,
    });

    const data = response.data;
    const token = data.access_token;

    localStorage.setItem("siem_jwt_token", token);
    localStorage.setItem("siem_authenticated", "true");
    localStorage.setItem("siem_role", data.user.role);
    localStorage.setItem("siem_email", data.user.email || email);
    localStorage.setItem("siem_username", data.user.username);

    const user: User = {
      id: data.user.user_id,
      username: data.user.username,
      email: data.user.email || email,
      hashed_password: "",
      role: toUserRole(data.user.role),
      mfa_secret: "",
      mfa_enabled: false,
      org_scope: data.user.org_scope ?? null,
      is_active: data.user.is_active,
      last_login_at: new Date().toISOString(),
      failed_login_count: 0,
      locked_until: null,
      created_at: "",
      created_by: null,
    };

    return { token, user };
  }

  async logout(): Promise<{ success: boolean }> {
    try {
      await this.request("POST", "/auth/logout", null);
    } catch {
      // Si l'API échoue, on nettoie quand même la session locale
    }
    localStorage.removeItem("siem_jwt_token");
    localStorage.removeItem("siem_authenticated");
    localStorage.removeItem("siem_role");
    localStorage.removeItem("siem_email");
    localStorage.removeItem("siem_username");
    return { success: true };
  }

  async getProfile(): Promise<User> {
    return this.request("GET", "/auth/me", null);
  }

  async verifyTotp(code: string): Promise<{ valid: boolean }> {
    return this.request("POST", "/auth/verify-totp", { totp_code: code });
  }
}
