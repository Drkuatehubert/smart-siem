// src/Services/logService.ts
import { BaseService } from "./baseService";
import type { LogEvent, RawLog, LogSource } from "../types";

const MOCK_LOG_EVENTS: LogEvent[] = [
  {
    "@timestamp": "2026-06-27T19:05:00Z",
    raw_log_id: "raw-001",
    source_id: "src-1",
    source_ip: "192.168.1.45",
    dest_ip: "10.0.0.12",
    dest_port: 22,
    host: "srv-prod-web-01",
    log_type: "auth",
    severity: "info",
    event_action: "login_success",
    username: "admin",
    process_name: "sshd",
    raw_message: "SSH login successful for user admin from 192.168.1.45",
    hash_sha256: "a1b2c3d4e5f6...",
    enriched_data: null,
    mitre_tactic: null,
    tags: [],
  },
  {
    "@timestamp": "2026-06-27T19:06:12Z",
    raw_log_id: "raw-002",
    source_id: "src-1",
    source_ip: "185.220.101.5",
    dest_ip: "10.0.0.12",
    dest_port: 22,
    host: "srv-prod-web-01",
    log_type: "auth",
    severity: "warning",
    event_action: "login_failed",
    username: "root",
    process_name: "sshd",
    raw_message: "SSH connection failed for user root: Invalid credentials",
    hash_sha256: "b2c3d4e5f6a7...",
    enriched_data: null,
    mitre_tactic: "TA0001",
    tags: ["brute_force_candidate"],
  },
  {
    "@timestamp": "2026-06-27T19:07:44Z",
    raw_log_id: "raw-003",
    source_id: "src-1",
    source_ip: "185.220.101.5",
    dest_ip: "10.0.0.12",
    dest_port: 22,
    host: "srv-prod-web-01",
    log_type: "auth",
    severity: "high",
    event_action: "login_failed",
    username: "root",
    process_name: "sshd",
    raw_message: "SSH connection failed for user root (Attempt 45/100)",
    hash_sha256: "c3d4e5f6a7b8...",
    enriched_data: null,
    mitre_tactic: "TA0001",
    tags: ["brute_force_candidate", "high_frequency"],
  },
  {
    "@timestamp": "2026-06-27T19:10:02Z",
    raw_log_id: "raw-005",
    source_id: "src-2",
    source_ip: "192.168.1.112",
    dest_ip: "10.0.4.50",
    dest_port: 443,
    host: "srv-file-share",
    log_type: "network",
    severity: "critical",
    event_action: "data_exfiltration",
    username: "j.martin",
    process_name: null,
    raw_message: "Anomalous volume of data transferred: 14.5 GB uploaded",
    hash_sha256: "d4e5f6a7b8c9...",
    enriched_data: { geoip: { country: "RU" } },
    mitre_tactic: "TA0010",
    tags: ["exfiltration", "high_volume"],
  },
  {
    "@timestamp": "2026-06-27T19:14:22Z",
    raw_log_id: "raw-008",
    source_id: "src-3",
    source_ip: "10.0.1.33",
    dest_ip: "198.51.100.22",
    dest_port: 443,
    host: "pc-marketing-01",
    log_type: "system",
    severity: "critical",
    event_action: "malware_detected",
    username: "a.dubois",
    process_name: "PowerShell.exe",
    raw_message: "Trojan:Win32/CobaltStrike.C downloaded by PowerShell.exe",
    hash_sha256: "e5f6a7b8c9d0...",
    enriched_data: null,
    mitre_tactic: "TA0005",
    tags: ["malware", "cobalt_strike"],
  },
];

const MOCK_RAW_LOGS: RawLog[] = [
  {
    id: "raw-001",
    received_at: "2026-06-27T19:05:00Z",
    raw_content:
      "<34>1 2026-06-27T19:05:00Z srv-prod-web-01 sshd - - sshd[1234]: Accepted password for admin",
    source_protocol: "syslog-udp",
    source_ip: "192.168.1.45",
    processing_status: "normalized",
    normalized_at: "2026-06-27T19:05:01Z",
    error_message: null,
    es_document_id: "es-doc-001",
  },
];

const MOCK_LOG_SOURCES: LogSource[] = [
  {
    id: "src-1",
    name: "srv-prod-web-01",
    source_type: "linux_server",
    ip_address: "10.0.0.12",
    hostname: "srv-prod-web-01.ctu.int",
    collection_protocol: "syslog-udp",
    collection_port: 514,
    environment: "production",
    is_active: true,
    last_seen_at: "2026-06-27T19:18:45Z",
    created_at: "2026-01-15T08:00:00Z",
  },
  {
    id: "src-2",
    name: "srv-file-share",
    source_type: "windows_server",
    ip_address: "10.0.4.50",
    hostname: "srv-file-share.ctu.int",
    collection_protocol: "filebeat",
    collection_port: 5044,
    environment: "production",
    is_active: true,
    last_seen_at: "2026-06-27T19:18:30Z",
    created_at: "2026-01-15T08:00:00Z",
  },
  {
    id: "src-3",
    name: "pc-marketing-01",
    source_type: "windows_server",
    ip_address: "10.0.1.33",
    hostname: "pc-marketing-01.ctu.int",
    collection_protocol: "filebeat",
    collection_port: 5044,
    environment: "production",
    is_active: true,
    last_seen_at: "2026-06-27T19:18:12Z",
    created_at: "2026-02-01T10:00:00Z",
  },
];

export class LogService extends BaseService {
  private logEvents = [...MOCK_LOG_EVENTS];

  async getLogs(): Promise<LogEvent[]> {
    return this.request("GET", "/logs", null, () => this.logEvents);
  }

  async getLogById(id: string): Promise<LogEvent> {
    return this.request("GET", `/logs/${id}`, null, () => {
      const found = this.logEvents.find(
        (l) => l.raw_log_id === id || l["@timestamp"] === id,
      );
      if (!found) throw new Error(`Log ${id} non trouvé`);
      return found;
    });
  }

  async getRawLogs(): Promise<RawLog[]> {
    return this.request("GET", "/raw-logs", null, () => MOCK_RAW_LOGS);
  }

  async getLogSources(): Promise<LogSource[]> {
    return this.request("GET", "/log-sources", null, () => MOCK_LOG_SOURCES);
  }
}
