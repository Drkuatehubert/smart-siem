// src/Services/authService.ts
import { BaseService } from "./baseService";
import type { User, UserRole } from "../types";

export class AuthService extends BaseService {
  async login(
    email: string,
    password?: string,
    totpCode?: string,
  ): Promise<{ token: string; user: User }> {
    return this.request(
      "POST",
      "/auth/login",
      { username: email, password },
      () => {
        // Simulation de l'authentification avec MFA TOTP
        let assignedRole: UserRole = "analyst";
        let username = "j.dupont";
        let name = "Jean Dupont";

        if (email.includes("admin") || email.includes("pierre")) {
          assignedRole = "admin";
          username = "p.durand";
          name = "Pierre Durand";
        } else if (email.includes("rssi") || email.includes("marc")) {
          assignedRole = "admin";
          username = "m.lemaire";
          name = "Marc Lemaire";
        } else if (email.includes("audit") || email.includes("externe")) {
          assignedRole = "reader";
          username = "auditeur";
          name = "Auditeur Externe";
        }

        // Vérification MFA simulée — tout code à 6 chiffres accepté sauf "000000"
        if (totpCode && totpCode === "000000") {
          throw new Error(
            "Code TOTP invalide — vérifiez votre application d'authentification",
          );
        }

        const mockUser: User = {
          id: `usr-${Date.now()}`,
          username,
          email,
          hashed_password: "$2b$12$mock_hash...",
          role: assignedRole,
          mfa_secret: "JBSWY3DPEHPK3PXP",
          mfa_enabled: true,
          org_scope: assignedRole === "admin" ? null : "SOC",
          is_active: true,
          last_login_at: new Date().toISOString(),
          failed_login_count: 0,
          locked_until: null,
          created_at: "2026-01-15T08:00:00Z",
          created_by: null,
        };

        const mockToken = `jwt_mock_token_for_${assignedRole}_${Date.now()}`;

        localStorage.setItem("siem_jwt_token", mockToken);
        localStorage.setItem("siem_authenticated", "true");
        localStorage.setItem("siem_role", assignedRole);
        localStorage.setItem("siem_email", email);
        localStorage.setItem("siem_username", username);

        return { token: mockToken, user: mockUser };
      },
    );
  }

  async logout(): Promise<{ success: boolean }> {
    return this.request("POST", "/auth/logout", null, () => {
      localStorage.removeItem("siem_jwt_token");
      localStorage.removeItem("siem_authenticated");
      localStorage.removeItem("siem_role");
      localStorage.removeItem("siem_email");
      localStorage.removeItem("siem_username");
      return { success: true };
    });
  }

  async getProfile(): Promise<User> {
    return this.request("GET", "/auth/profile", null, () => {
      const email =
        localStorage.getItem("siem_email") || "jean.dupont@smart-siem.com";
      const role = (localStorage.getItem("siem_role") as UserRole) || "analyst";
      const username = localStorage.getItem("siem_username") || "j.dupont";

      return {
        id: "usr-current",
        username,
        email,
        hashed_password: "",
        role,
        mfa_secret: "JBSWY3DPEHPK3PXP",
        mfa_enabled: true,
        org_scope: null,
        is_active: true,
        last_login_at: new Date().toISOString(),
        failed_login_count: 0,
        locked_until: null,
        created_at: "2026-01-15T08:00:00Z",
        created_by: null,
      };
    });
  }

  async verifyTotp(code: string): Promise<{ valid: boolean }> {
    return this.request(
      "POST",
      "/auth/verify-totp",
      { totp_code: code },
      () => {
        if (code === "000000") {
          return { valid: false };
        }
        return { valid: true };
      },
    );
  }
}
