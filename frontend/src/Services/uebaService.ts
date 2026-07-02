// src/Services/uebaService.ts
import { BaseService } from "./baseService";
import type { UebaProfile } from "../types";

const MOCK_UEBA_PROFILES: UebaProfile[] = [
  {
    entity_id: "j.martin",
    entity_type: "user",
    profile_period_start: "2026-05-28T00:00:00Z",
    profile_period_end: "2026-06-27T23:59:59Z",
    typical_login_hours: {
      peak_hours: [8, 9, 10, 11, 14, 15, 16, 17],
      off_hours: [0, 1, 2, 3, 4, 22, 23],
    },
    typical_source_ips: ["10.0.1.10", "192.168.1.100"],
    avg_daily_events: 245,
    avg_daily_data_volume_mb: 120.5,
    typical_accessed_systems: ["srv-file-share", "srv-prod-web-01"],
    risk_score_current: 92,
    risk_score_history: [
      { score: 15, timestamp: "2026-06-20T00:00:00Z" },
      { score: 22, timestamp: "2026-06-22T00:00:00Z" },
      { score: 45, timestamp: "2026-06-25T00:00:00Z" },
      { score: 92, timestamp: "2026-06-27T19:10:00Z" },
    ],
    anomalies_detected: [
      {
        timestamp: "2026-06-27T19:10:02Z",
        description:
          "Exfiltration suspecte de 14.5 Go de données vers un serveur inconnu",
        risk_score: 92,
      },
    ],
    last_updated: "2026-06-27T19:10:05Z",
  },
  {
    entity_id: "s.rodriguez",
    entity_type: "user",
    profile_period_start: "2026-05-28T00:00:00Z",
    profile_period_end: "2026-06-27T23:59:59Z",
    typical_login_hours: {
      peak_hours: [9, 10, 11, 14, 15, 16],
      off_hours: [0, 1, 2, 3, 4, 5, 22, 23],
    },
    typical_source_ips: ["10.0.2.80", "192.168.2.50"],
    avg_daily_events: 180,
    avg_daily_data_volume_mb: 85.2,
    typical_accessed_systems: ["srv-dev-01", "srv-gitlab"],
    risk_score_current: 74,
    risk_score_history: [
      { score: 10, timestamp: "2026-06-20T00:00:00Z" },
      { score: 74, timestamp: "2026-06-27T19:12:05Z" },
    ],
    anomalies_detected: [
      {
        timestamp: "2026-06-27T19:12:05Z",
        description:
          "Scan de ports rapide initié vers 45 serveurs en moins de 30 secondes",
        risk_score: 74,
      },
    ],
    last_updated: "2026-06-27T19:12:10Z",
  },
  {
    entity_id: "srv-prod-web-01",
    entity_type: "machine",
    profile_period_start: "2026-05-28T00:00:00Z",
    profile_period_end: "2026-06-27T23:59:59Z",
    typical_login_hours: {
      peak_hours: [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23,
      ],
      off_hours: [],
    },
    typical_source_ips: ["10.0.0.0/8", "192.168.0.0/16"],
    avg_daily_events: 12500,
    avg_daily_data_volume_mb: 4500,
    typical_accessed_systems: ["db-primary", "ldap.ctu.int"],
    risk_score_current: 85,
    risk_score_history: [
      { score: 12, timestamp: "2026-06-20T00:00:00Z" },
      { score: 85, timestamp: "2026-06-27T19:05:00Z" },
    ],
    anomalies_detected: [
      {
        timestamp: "2026-06-27T19:05:00Z",
        description:
          "Authentification SSH réussie depuis une IP suspecte (Tor exit node)",
        risk_score: 85,
      },
    ],
    last_updated: "2026-06-27T19:05:05Z",
  },
];

export class UebaService extends BaseService {
  private profiles = [...MOCK_UEBA_PROFILES];

  async getProfiles(): Promise<UebaProfile[]> {
    return this.request("GET", "/ueba/profiles", null, () => this.profiles);
  }

  async getProfileByEntity(entityId: string): Promise<UebaProfile | undefined> {
    return this.request("GET", `/ueba/profiles/${entityId}`, null, () =>
      this.profiles.find((p) => p.entity_id === entityId),
    );
  }
}
