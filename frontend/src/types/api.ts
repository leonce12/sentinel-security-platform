// Types mirror the backend response schemas (backend/app/schemas).

export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface UserRef {
  id: number;
  username: string;
  full_name: string;
}

export interface Me {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: string;
  role_display_name: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
  permissions: string[];
}

export interface UserRow {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface SecurityEvent {
  id: number;
  event_uid: string;
  timestamp: string;
  source_system: string;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  event_category: string;
  event_type: string;
  severity: Severity;
  action: string | null;
  outcome: string | null;
  resource: string | null;
  description: string;
  risk_score: number | null;
  is_synthetic: boolean;
  ingestion_job_id: number | null;
  ingested_at: string;
}

export interface AlertBrief {
  id: number;
  rule_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  status: string;
  incident_id: number | null;
}

export interface IncidentBrief {
  id: number;
  reference: string;
  title: string;
  status: string;
  severity: Severity;
}

export interface EventDetail extends SecurityEvent {
  raw_data: Record<string, unknown>;
  alerts: AlertBrief[];
  incidents: IncidentBrief[];
}

export interface IngestionJob {
  id: number;
  source_type: string;
  filename: string | null;
  status: string;
  total_records: number;
  processed_records: number;
  rejected_records: number;
  duplicate_records: number;
  duration_ms: number;
  errors: { record: number | null; errors: { field: string; message: string }[] }[];
  warnings: { record: number; warnings: string[] }[];
  is_synthetic: boolean;
  detection_summary: DetectionSummary | null;
  created_at: string;
}

export interface DetectionSummary {
  rules_evaluated: number;
  events_considered: number;
  findings: number;
  alerts_created: number;
  alerts_updated: number;
  unchanged: number;
  incidents_created: number;
  duration_ms: number;
  per_rule: Record<string, { relevant_events: number; findings: number; created: number; updated: number; unchanged: number }>;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  base_score: number;
  confidence: number;
  parameters: Record<string, number | boolean | string[]>;
  required_fields: string[];
  rationale: string;
  investigation_steps: string[];
  false_positive_notes: string;
  enabled: boolean;
  updated_at: string;
}

export interface ScoreFactor {
  factor: string;
  points: number;
  explanation: string;
}

export interface Alert {
  id: number;
  rule_id: string;
  rule_name: string;
  group_key: string;
  title: string;
  description: string;
  severity: Severity;
  risk_score: number;
  status: string;
  event_count: number;
  first_seen: string;
  last_seen: string;
  assigned_to: UserRef | null;
  incident_id: number | null;
  incident_reference: string | null;
  is_synthetic: boolean;
  created_at: string;
}

export interface Activity {
  id: number;
  activity_type: string;
  from_value: string | null;
  to_value: string | null;
  note: string;
  actor: UserRef | null;
  created_at: string;
}

export interface AlertDetail extends Alert {
  score_breakdown: ScoreFactor[];
  evidence_summary: Record<string, unknown>;
  rule: Rule;
  acknowledged_at: string | null;
  activity: Activity[];
  events: SecurityEvent[];
  events_total: number;
}

export interface Incident {
  id: number;
  reference: string;
  title: string;
  description: string;
  severity: Severity;
  risk_score: number;
  status: string;
  affected_entities: { accounts?: string[]; systems?: string[]; ips?: string[] };
  detected_at: string;
  assigned_to: UserRef | null;
  resolution: string | null;
  closed_at: string | null;
  auto_created: boolean;
  is_synthetic: boolean;
  alert_count: number;
  created_at: string;
  updated_at: string;
}

export interface IncidentDetail extends Incident {
  alerts: AlertBrief[];
  notes: { id: number; body: string; author: UserRef | null; created_at: string }[];
  history: {
    id: number;
    change_type: string;
    from_value: string | null;
    to_value: string | null;
    details: string;
    actor: UserRef | null;
    created_at: string;
  }[];
}

export interface Lookup {
  id: number;
  indicator: string;
  provider: string;
  verdict: "malicious" | "suspicious" | "no_detections" | "no_information" | "unavailable";
  confidence: number | null;
  details: Record<string, unknown>;
  limitations: string;
  looked_up_at: string;
  expires_at: string | null;
}

export interface Indicator {
  id: number;
  indicator: string;
  indicator_type: string;
  verdict: string;
  confidence: number;
  source: string;
  description: string;
  is_synthetic: boolean;
  added_at: string;
}

export interface AnomalyResult {
  id: number;
  entity: string;
  window_start: string;
  window_end: string;
  features: Record<string, number>;
  anomaly_score: number;
  is_anomaly: boolean;
  contributing_features: { feature: string; value: number; baseline_mean: number; z_score: number }[];
  model_version: string;
  review_status: string;
  review_note: string;
  reviewed_at: string | null;
  is_synthetic: boolean;
}

export interface Report {
  id: number;
  report_type: string;
  title: string;
  parameters: Record<string, unknown>;
  period_start: string | null;
  period_end: string | null;
  summary: Record<string, unknown>;
  sha256: string;
  size_bytes: number;
  generated_by: UserRef | null;
  generated_at: string;
}

export interface Notification {
  id: number;
  notification_type: string;
  title: string;
  message: string;
  link: string | null;
  is_read: boolean;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  actor_username: string | null;
  action: string;
  object_type: string | null;
  object_id: string | null;
  outcome: string;
  ip_address: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface DashboardSummary {
  range: { start: string; end: string };
  total_events: number;
  total_alerts: number;
  open_alerts: number;
  open_incidents: number;
  critical_incidents: number;
  high_risk_events: number;
  events_requiring_investigation: number;
  auth_failures: number;
  synthetic_events: number;
  ingestion: {
    total_jobs: number;
    failed_jobs_24h: number;
    last_job: null | {
      id: number;
      status: string;
      filename: string | null;
      created_at: string;
      processed: number;
      rejected: number;
      duplicates: number;
    };
  };
}

export interface DashboardAnalytics {
  range: { start: string; end: string; bucket: "hour" | "day" };
  events_over_time: ({ bucket: string; total: number } & Record<Severity, number>)[];
  auth_activity: { bucket: string; success: number; failure: number; other: number }[];
  alerts_by_severity: { severity: Severity; count: number }[];
  event_categories: { category: string; count: number }[];
  top_sources: { source: string; count: number }[];
  incident_status: { status: string; count: number }[];
  risk_distribution: { band: string; count: number }[];
  rule_performance: {
    rule_id: string;
    name: string;
    enabled: boolean;
    alerts: number;
    false_positives: number;
    open: number;
    avg_score: number | null;
  }[];
}

export interface AiExplanation {
  source: string;
  summary: string;
  what_happened?: string[];
  why_flagged?: string;
  risk_score_meaning?: string[];
  facts?: string[];
  assumptions?: string[];
  missing_information?: string[];
  recommended_steps?: string[];
  false_positive_considerations?: string[];
  details?: string[];
  answer?: string;
  matches?: { term: string; definition: string }[];
}

export interface AiResponse {
  deterministic: AiExplanation;
  ai: AiExplanation | null;
  ai_status: string;
}
