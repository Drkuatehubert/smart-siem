// ===== RÔLES RBAC (conforme dictionnaire : reader, analyst, admin) =====
export type UserRole = "reader" | "analyst" | "admin";

// ===== 4.8 — users (PostgreSQL) =====
export interface User {
  id: string;
  username: string;
  email: string;
  hashed_password: string;
  role: UserRole;
  mfa_secret: string;
  mfa_enabled: boolean;
  org_scope: string | null;
  is_active: boolean;
  last_login_at: string | null;
  failed_login_count: number;
  locked_until: string | null;
  created_at: string;
  created_by: string | null;
}

// ===== 4.1 — raw_logs (PostgreSQL) =====
export interface RawLog {
  id: string;
  received_at: string;
  raw_content: string;
  source_protocol: "syslog-udp" | "syslog-tcp" | "filebeat" | "rest-api";
  source_ip: string;
  processing_status: "pending" | "processing" | "normalized" | "error";
  normalized_at: string | null;
  error_message: string | null;
  es_document_id: string | null;
}

// ===== 4.2 — log_sources (PostgreSQL) =====
export interface LogSource {
  id: string;
  name: string;
  source_type:
    | "linux_server"
    | "windows_server"
    | "firewall"
    | "web_server"
    | "active_directory"
    | "cloud_aws"
    | "application";
  ip_address: string;
  hostname: string | null;
  collection_protocol: "syslog-udp" | "syslog-tcp" | "filebeat" | "rest";
  collection_port: number;
  environment: "production" | "development" | "test";
  is_active: boolean;
  last_seen_at: string | null;
  created_at: string;
}

// ===== 4.3 — log_events (Elasticsearch) =====
export type LogType = "auth" | "network" | "system" | "application" | "audit";
export type SeverityLevel = "info" | "warning" | "high" | "critical";

export interface LogEvent {
  "@timestamp": string;
  raw_log_id: string;
  source_id: string;
  source_ip: string;
  dest_ip: string | null;
  dest_port: number | null;
  host: string;
  log_type: LogType;
  severity: SeverityLevel;
  event_action: string;
  username: string | null;
  process_name: string | null;
  raw_message: string;
  hash_sha256: string | null;
  enriched_data: Record<string, unknown> | null;
  mitre_tactic: string | null;
  tags: string[];
}

// ===== 4.4 — correlation_rules (PostgreSQL) =====
export type RuleType = "threshold" | "pattern" | "behavioral" | "composite" | "cross_source";

export interface CorrelationRule {
  id: string;
  name: string;
  description: string;
  rule_type: RuleType;
  conditions: Record<string, unknown>;
  time_window_seconds: number | null;
  threshold_count: number | null;
  sources_required: string[] | null;
  alert_level: SeverityLevel;
  confidence_score: number;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  playbook_id: string | null;
  is_active: boolean;
  false_positive_count: number;
  created_by: string;
}

// ===== 4.5 — alerts (PostgreSQL) =====
export type AlertStatus =
  "open" | "investigating" | "false_positive" | "confirmed" | "escalated";

export interface Alert {
  id: string;
  rule_id: string;
  title: string;
  level: SeverityLevel;
  status: AlertStatus;
  triggered_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  acknowledged_by: string | null;
  correlated_event_ids: string[];
  source_ips: string[];
  affected_hosts: string[];
  confidence_score: number;
  mitre_tactic: string | null;
  notes: string | null;
}

// ===== 4.6 — incidents (PostgreSQL) =====
export type IncidentStatus =
  "open" | "in_progress" | "pending_action" | "resolved" | "closed";

export interface Incident {
  id: string;
  alert_id: string;
  title: string;
  severity: SeverityLevel;
  status: IncidentStatus;
  assigned_to: string | null;
  opened_at: string;
  resolved_at: string | null;
  response_actions: ResponseAction[];
  affected_assets: AffectedAsset[];
  root_cause: string | null;
  lessons_learned: string | null;
  ioc_indicators: IocIndicator[];
}

export interface ResponseAction {
  action: string;
  target: string;
  by: string;
  at: string;
}

export interface AffectedAsset {
  type: "ip" | "host" | "user_account";
  value: string;
}

export interface IocIndicator {
  type: "ip" | "hash" | "domain" | "url";
  value: string;
}

// ===== 4.7 — playbooks (PostgreSQL) =====
export type ActionType =
  | "block_ip"
  | "disable_account"
  | "isolate_machine"
  | "notify_escalation"
  | "collect_evidence";
export type ExecutionMode = "AUTO" | "CONFIRM";

export interface Playbook {
  id: string;
  name: string;
  description: string;
  action_type: ActionType;
  execution_mode: ExecutionMode;
  parameters: Record<string, unknown>;
  target_type: "ip_address" | "user_account" | "machine" | "subnet" | null;
  confirmation_timeout_seconds: number;
  is_active: boolean;
  execution_count: number;
  last_executed_at: string | null;
  created_by: string;
}

// ===== 4.9 — audit_logs (PostgreSQL) =====
export type AuditResult = "success" | "failure" | "denied";

export interface AuditLog {
  id: string;
  user_id: string;
  username_snapshot: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  performed_at: string;
  ip_address: string | null;
  user_agent: string | null;
  result: AuditResult;
  metadata: Record<string, unknown> | null;
}

// ===== 4.10 — ueba_profiles (Elasticsearch) =====
export type EntityType = "user" | "machine";

export interface UebaProfile {
  entity_id: string;
  entity_type: EntityType;
  profile_period_start: string;
  profile_period_end: string;
  typical_login_hours: TypicalLoginHours;
  typical_source_ips: string[];
  avg_daily_events: number;
  avg_daily_data_volume_mb: number;
  typical_accessed_systems: string[];
  risk_score_current: number;
  risk_score_history: RiskScoreEntry[];
  anomalies_detected: AnomalyEntry[];
  last_updated: string;
}

export interface TypicalLoginHours {
  peak_hours: number[];
  off_hours: number[];
}

export interface RiskScoreEntry {
  score: number;
  timestamp: string;
}

export interface AnomalyEntry {
  timestamp: string;
  description: string;
  risk_score: number;
}

// ===== Types conservés mais renommés / adaptés =====

// ThreatIndicator — pas dans le dictionnaire mais utile pour le frontend
export interface ThreatIndicator {
  id: string;
  indicator: string;
  type: "IP" | "DOMAIN" | "HASH_SHA256";
  threat_type: string;
  confidence: number;
  source: string;
  last_seen: string;
  reputation: "MALICIOUS" | "SUSPICIOUS" | "BENIGN";
}

// EndpointAgent — adapté, proche de log_sources mais avec monitoring agent
export interface EndpointAgent {
  id: string;
  hostname: string;
  ip_address: string;
  source_type: string;
  os: string;
  version: string;
  status: "ONLINE" | "OFFLINE" | "UNSTABLE";
  last_ping: string;
  logs_sent: number;
  cpu_usage: number;
  memory_usage: number;
}

// Vulnerability — pas dans le dictionnaire mais conservé
export interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  description: string;
  cvss_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  affected_asset: string;
  status: "OPEN" | "PATCHED" | "RISK_ACCEPTED";
  discovered_at: string;
  remediation_steps: string;
}

// ComplianceControl — pas dans le dictionnaire mais conservé
export interface ComplianceControl {
  id: string;
  standard: string;
  section: string;
  control_name: string;
  description: string;
  status: "COMPLIANT" | "PARTIAL" | "NON_COMPLIANT";
  evidence: string;
  last_audit: string;
}

// SecurityReport — conservé
export interface SecurityReport {
  id: string;
  title: string;
  type: "DAILY" | "WEEKLY" | "MONTHLY" | "COMPLIANCE";
  generated_by: string;
  created_at: string;
  format: string;
  size: string;
}
