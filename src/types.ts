export type UserRole = 'SOC_ANALYST' | 'ADMIN' | 'AUDITOR' | 'RSSI';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatar: string;
}

export interface Incident {
  comments: any;
  id: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'NEW' | 'INVESTIGATING' | 'MITIGATED' | 'CLOSED';
  assignee: string;
  created_at: string;
  updated_at: string;
  category: string;
  logs_count: number;
}

export interface SecurityLog {
  category: string;
  id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  port: number;
  protocol: string;
  event_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  message: string;
  hostname: string;
  username: string;
}

// ===== TYPES MANQUANTS À AJOUTER =====

export interface CorrelationRule {
  id: string;
  name: string;
  description: string;
  query: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  is_active: boolean;
  category: string;
  created_by: string;
  created_at: string;
}

export interface ThreatIndicator {
  id: string;
  indicator: string;
  type: 'IP' | 'DOMAIN' | 'HASH_SHA256';
  threat_type: string;
  confidence: number;
  source: string;
  last_seen: string;
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
}

export interface EndpointAgent {
  id: string;
  hostname: string;
  ip_address: string;
  os: string;
  version: string;
  status: 'ONLINE' | 'OFFLINE' | 'UNSTABLE';
  last_ping: string;
  logs_sent: number;
  cpu_usage: number;
  memory_usage: number;
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  description: string;
  cvss_score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  affected_asset: string;
  status: 'OPEN' | 'PATCHED' | 'RISK_ACCEPTED';
  discovered_at: string;
  remediation_steps: string;
}

export interface SOARPlaybook {
  id: string;
  name: string;
  description: string;
  trigger_event: string;
  steps: string[];
  is_active: boolean;
  last_triggered: string | null;
  executions_count: number;
}

export interface ComplianceControl {
  id: string;
  standard: string;
  section: string;
  control_name: string;
  description: string;
  status: 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT';
  evidence: string;
  last_audit: string;
}

export interface SystemAuditLog {
  id: string;
  timestamp: string;
  user: string;
  role: UserRole;
  action: string;
  target: string;
  status: 'SUCCESS' | 'FAILED';
  ip_address: string;
}

export interface UebaAnomaly {
  id: string;
  user_or_entity: string;
  type: string;
  risk_score: number;
  anomaly_description: string;
  timestamp: string;
  category: string;
}

export interface SecurityReport {
  id: string;
  title: string;
  type: 'DAILY' | 'WEEKLY' | 'MONTHLY' | 'COMPLIANCE';
  generated_by: string;
  created_at: string;
  format: string;
  size: string;
}