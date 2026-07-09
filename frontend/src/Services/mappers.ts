import type {
  Alert,
  CorrelationRule,
  EndpointAgent,
  Incident,
  LogEvent,
  Playbook,
  SeverityLevel,
  UebaProfile,
  User,
  UserRole,
} from "../types";

type Row = Record<string, unknown>;

export function unwrapResults<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object" && "results" in data) {
    return ((data as { results?: T[] }).results ?? []) as T[];
  }
  if (data && typeof data === "object" && "items" in data) {
    return ((data as { items?: T[] }).items ?? []) as T[];
  }
  return [];
}

export function mapSeverity(level: unknown): SeverityLevel {
  const key = String(level ?? "info").toUpperCase();
  const map: Record<string, SeverityLevel> = {
    CRITICAL: "critical",
    HIGH: "high",
    WARNING: "warning",
    INFO: "info",
  };
  return map[key] ?? "info";
}

export function mapFrontendRole(role: unknown): UserRole {
  const key = String(role ?? "reader").toLowerCase();
  const map: Record<string, UserRole> = {
    administrateur: "admin",
    admin: "admin",
    analyste: "analyst",
    analyst: "analyst",
    rssi: "rssi",
    auditeur: "auditor",
    auditor: "auditor",
    lecteur: "reader",
    reader: "reader",
  };
  return map[key] ?? "reader";
}

function asArray<T>(value: unknown): T[] {
  if (Array.isArray(value)) return value as T[];
  return [];
}

function asObjectArray(value: unknown): Row[] {
  if (Array.isArray(value)) return value as Row[];
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).map(([k, v]) => ({
      type: k,
      value: String(v),
    }));
  }
  return [];
}

export function mapIncident(row: Row): Incident {
  return {
    id: String(row.id ?? ""),
    alert_id: String(row.alert_id ?? ""),
    title: String(row.title ?? row.titre ?? ""),
    severity: mapSeverity(row.severity ?? row.priorite),
    status: String(row.status ?? row.statut ?? "open") as Incident["status"],
    assigned_to: row.assigned_to ? String(row.assigned_to) : null,
    opened_at: String(row.opened_at ?? row.created_at ?? ""),
    resolved_at: row.resolved_at ? String(row.resolved_at) : null,
    response_actions: asArray(row.response_actions),
    affected_assets: asObjectArray(row.affected_assets) as unknown as Incident["affected_assets"],
    root_cause: row.root_cause ? String(row.root_cause) : null,
    lessons_learned: row.lessons_learned ? String(row.lessons_learned) : null,
    ioc_indicators: asArray(row.ioc_indicators),
    alert_title: row.alert_title ? String(row.alert_title) : undefined,
    alert_level: row.alert_level ? String(row.alert_level) : undefined,
  };
}

export function mapRule(row: Row): CorrelationRule {
  return {
    id: String(row.id ?? ""),
    name: String(row.name ?? row.nom ?? ""),
    description: String(row.description ?? ""),
    rule_type: String(row.rule_type ?? row.type ?? "threshold") as CorrelationRule["rule_type"],
    conditions: (row.conditions ?? row.condition ?? {}) as Record<string, unknown>,
    time_window_seconds:
      row.time_window_seconds != null ? Number(row.time_window_seconds) : null,
    threshold_count: row.threshold_count != null ? Number(row.threshold_count) : null,
    sources_required: row.sources_required ? asArray<string>(row.sources_required) : null,
    alert_level: mapSeverity(row.alert_level ?? row.niveau_alerte_genere),
    confidence_score: Number(row.confidence_score ?? 0),
    mitre_tactic: row.mitre_tactic ? String(row.mitre_tactic) : null,
    mitre_technique: row.mitre_technique ? String(row.mitre_technique) : null,
    playbook_id: row.playbook_id ? String(row.playbook_id) : null,
    is_active: Boolean(row.is_active ?? row.active ?? true),
    false_positive_count: Number(row.false_positive_count ?? 0),
    created_by: String(row.created_by ?? ""),
  };
}

export function mapAgent(row: Row): EndpointAgent {
  const statusRaw = String(row.status ?? "active").toUpperCase();
  const status =
    statusRaw === "ACTIVE" || statusRaw === "ONLINE"
      ? "ONLINE"
      : statusRaw === "INACTIVE" || statusRaw === "OFFLINE"
        ? "OFFLINE"
        : "UNSTABLE";

  return {
    id: String(row.id ?? ""),
    hostname: String(row.hostname ?? row.name ?? row.host ?? row.id ?? ""),
    ip_address: String(row.host ?? row.ip_address ?? ""),
    source_type: String(row.source_type ?? "linux_server") as EndpointAgent["source_type"],
    os: String(row.os ?? "Unknown"),
    version: String(row.version ?? "Agent SIEM"),
    status,
    last_ping: String(row.last_seen ?? row.last_ping ?? new Date().toISOString()),
    logs_sent: Number(row.logs_sent ?? 0),
    cpu_usage: Number(row.cpu_usage ?? 0),
    memory_usage: Number(row.memory_usage ?? 0),
  };
}

export function mapUebaProfile(row: Row): UebaProfile {
  const typicalLogin = (row.typical_login_hours ?? {}) as Record<string, number[]>;
  const previous = row.risk_score_previous != null ? Number(row.risk_score_previous) : null;
  const current = Number(row.risk_score_current ?? 0);
  const lastUpdated = String(row.last_updated ?? new Date().toISOString());

  return {
    entity_id: String(row.entity_id ?? ""),
    entity_type: String(row.entity_type ?? "user") as UebaProfile["entity_type"],
    profile_period_start: String(row.profile_period_start ?? ""),
    profile_period_end: String(row.profile_period_end ?? ""),
    typical_login_hours: {
      peak_hours: typicalLogin.peak_hours ?? [],
      off_hours: typicalLogin.off_hours ?? [],
    },
    typical_source_ips: asArray<string>(row.typical_source_ips),
    avg_daily_events: Number(row.avg_daily_events ?? 0),
    avg_daily_data_volume_mb: Number(row.avg_daily_data_mb ?? row.avg_daily_data_volume_mb ?? 0),
    typical_accessed_systems: asArray<string>(row.typical_accessed_systems),
    risk_score_current: current,
    risk_score_history:
      previous != null
        ? [
            { score: previous, timestamp: lastUpdated },
            { score: current, timestamp: lastUpdated },
          ]
        : [{ score: current, timestamp: lastUpdated }],
    anomalies_detected:
      row.last_anomaly_at
        ? [
            {
              timestamp: String(row.last_anomaly_at),
              description: `${Number(row.anomaly_count_7d ?? 0)} anomalie(s) détectée(s) sur 7 jours`,
              risk_score: current,
            },
          ]
        : [],
    last_updated: lastUpdated,
  };
}

export function mapUser(row: Row): User {
  return {
    id: String(row.id ?? ""),
    username: String(row.username ?? ""),
    email: String(row.email ?? ""),
    hashed_password: "",
    role: mapFrontendRole(row.role ?? row.role_id),
    mfa_secret: "",
    mfa_enabled: Boolean(row.mfa_enabled ?? false),
    org_scope: row.org_scope ? String(row.org_scope) : null,
    is_active: Boolean(row.is_active ?? true),
    last_login_at: row.last_login_at ? String(row.last_login_at) : null,
    failed_login_count: Number(row.failed_login_count ?? 0),
    locked_until: row.locked_until ? String(row.locked_until) : null,
    created_at: String(row.created_at ?? ""),
    created_by: row.created_by ? String(row.created_by) : null,
  };
}

export function mapPlaybook(row: Row): Playbook {
  return {
    id: String(row.id ?? ""),
    name: String(row.name ?? ""),
    description: String(row.description ?? ""),
    action_type: String(row.action_type ?? "custom") as Playbook["action_type"],
    execution_mode: String(row.execution_mode ?? "CONFIRM") as Playbook["execution_mode"],
    parameters: (row.parameters ?? {}) as Record<string, unknown>,
    target_type: row.target_type
      ? (String(row.target_type) as Playbook["target_type"])
      : null,
    confirmation_timeout_seconds: Number(row.confirmation_timeout_seconds ?? 300),
    is_active: Boolean(row.is_active ?? true),
    execution_count: Number(row.execution_count ?? 0),
    last_executed_at: row.last_executed_at ? String(row.last_executed_at) : null,
    created_by: String(row.created_by ?? ""),
  };
}

export function mapAlert(row: Row): Alert {
  return {
    id: String(row.id ?? ""),
    rule_id: String(row.rule_id ?? row.pg_alert_id ?? ""),
    rule_name: row.rule_name ? String(row.rule_name) : null,
    title: String(row.title ?? ""),
    level: mapSeverity(row.level ?? row.niveau),
    status: String(row.status ?? row.statut ?? "open") as Alert["status"],
    triggered_at: String(row.triggered_at ?? row["@timestamp"] ?? ""),
    acknowledged_at: row.acknowledged_at ? String(row.acknowledged_at) : null,
    resolved_at: row.resolved_at ? String(row.resolved_at) : null,
    acknowledged_by: row.acknowledged_by ? String(row.acknowledged_by) : null,
    correlated_event_ids: asArray<string>(row.correlated_event_ids),
    source_ips: asArray<string>(row.source_ips),
    affected_hosts: asArray<string>(row.affected_hosts),
    confidence_score: Number(row.confidence_score ?? 0),
    mitre_tactic: row.mitre_tactic ? String(row.mitre_tactic) : null,
    notes: row.notes ? String(row.notes) : null,
  };
}

export function mapLogEvent(row: Row): LogEvent {
  return {
    "@timestamp": String(row["@timestamp"] ?? row.timestamp ?? ""),
    raw_log_id: String(row.raw_log_id ?? row.id ?? ""),
    source_id: String(row.source_id ?? ""),
    source_ip: String(row.source_ip ?? row.host ?? ""),
    dest_ip: row.dest_ip ? String(row.dest_ip) : null,
    dest_port: row.dest_port != null ? Number(row.dest_port) : null,
    host: String(row.host ?? row.hostname ?? ""),
    log_type: String(row.log_type ?? "system") as LogEvent["log_type"],
    severity: mapSeverity(row.severity ?? row.level),
    event_action: String(row.event_action ?? row.action ?? ""),
    username: row.username ? String(row.username) : null,
    process_name: row.process_name ? String(row.process_name) : null,
    raw_message: String(row.raw_message ?? row.message ?? ""),
    hash_sha256: row.hash_sha256 ? String(row.hash_sha256) : null,
    enriched_data: (row.enriched_data ?? null) as Record<string, unknown> | null,
    mitre_tactic: row.mitre_tactic ? String(row.mitre_tactic) : null,
    tags: asArray<string>(row.tags),
  };
}
