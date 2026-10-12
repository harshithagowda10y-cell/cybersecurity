/**
 * MAS-CSI: Multi-Agent Systems for Cyber Security Intelligence
 * Strict Evidence-Driven Domain Types
 */

export type DetectionState = 'NORMAL' | 'SUSPICIOUS' | 'CONFIRMED' | 'ABSTAINED';

export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

export type UserRole = 'Super Admin' | 'Security Analyst' | 'Auditor' | 'Employee';

export type AttackScenario = 
  | 'BRUTE_FORCE'
  | 'PORT_SCAN'
  | 'DNS_ANOMALY'
  | 'WEB_ATTACK'
  | 'DATA_EXFILTRATION'
  | 'ACCOUNT_TAKEOVER'
  | 'AGENT_ANOMALY';

export type PageId =
  | 'command_center'
  | 'live_soc'
  | 'incidents'
  | 'ai_agents'
  | 'genai'
  | 'threat_intel'
  | 'hack_predictor'
  | 'security_tools'
  | 'attack_graph'
  | 'forensics'
  | 'evidence_vault'
  | 'location_intel'
  | 'reports'
  | 'real_lab'
  | 'admin_center';

export interface FileAuditEntry {
  audit_id: string;
  timestamp: string;
  modified_by: string;
  action: 'CREATED' | 'EDITED' | 'TAMPERED' | 'RESTORED';
  previous_sha256: string;
  new_sha256: string;
  is_authorized: boolean;
  notes: string;
}

export interface SecureLabFile {
  file_id: string;
  name: string;
  content: string;
  size_bytes: number;
  created_at: string;
  created_by: string;
  last_modified_at: string;
  last_modified_by: string;
  original_sha256: string;
  current_sha256: string;
  is_tampered: boolean;
  history: FileAuditEntry[];
  classification?: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  is_canary_trap?: boolean;
  canary_tripped?: boolean;
  canary_trip_details?: {
    tripped_by: string;
    timestamp: string;
    ip: string;
  } | null;
  digital_signature?: string | null;
  signed_by?: string | null;
  signed_at?: string | null;
  file_type?: 'DOCUMENT_PDF' | 'IMAGE' | 'TEXT' | 'SOURCE_CODE' | 'CONFIG' | 'KEY_PAIR';
  mime_type?: string;
  data_url?: string;
  importance?: 'CRITICAL' | 'HIGH' | 'NORMAL';
  notes?: string;
}

export interface EmployeeSecretItem {
  secret_id: string;
  title: string;
  category: 'API_TOKEN' | 'SSH_KEY' | 'SERVICE_PASSWORD' | 'CERTIFICATE';
  encrypted_value: string;
  sha256_checksum: string;
  created_at: string;
  owner_username: string;
}

export interface SystemSecurityPolicy {
  emergency_lockdown_active: boolean;
  mfa_enforced: boolean;
  session_timeout_minutes: number;
  max_failed_logins_before_lockout: number;
  tamper_auto_isolate_endpoint: boolean;
  zero_trust_strict_mode: boolean;
}

export interface FirewallRule {
  rule_id: string;
  direction: 'INBOUND' | 'OUTBOUND';
  source: string;
  destination: string;
  port: number | string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ANY';
  action: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  created_by: string;
  created_at: string;
  is_active: boolean;
}

export interface ThreatPrediction {
  prediction_id: string;
  generated_at: string;
  overall_threat_probability: number; // 0-100%
  attack_stage: 'Reconnaissance' | 'Initial Access' | 'Credential Stuffing' | 'Privilege Escalation' | 'Data Exfiltration' | 'Dormant';
  forecasted_incident_type: string;
  estimated_time_to_breach: string;
  contributing_indicators: string[];
  preventative_recommendations: string[];
  confidence_score: number;
}

export interface TelemetryEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  username: string;
  device_id: string;
  session_id: string;
  user_agent: string;
  request_method: string;
  request_path: string;
  request_status: number;
  bytes_in: number;
  bytes_out: number;
  city: string;
  country: string;
  latitude: number | null;
  longitude: number | null;
  location_label: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  message: string;
  raw_event: string;
  event_source: string;
  risk_score: number;
  ml_label: string;
  ml_confidence: number;
  ml_anomaly: boolean;
  evidence_quality: 'HIGH' | 'MEDIUM' | 'LOW';
  detection_state: DetectionState;
  detection_reason: string;
  mitre_technique: string;
  mitre_tactic: string;
  is_lab_scenario?: boolean;
}

export interface Incident {
  incident_id: string;
  created_at: string;
  first_seen: string;
  last_seen: string;
  event_id: string;
  title: string;
  attack_type: string;
  detection_state: DetectionState;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score: number;
  confidence: number;
  source_ip: string;
  actor_identity: string; // Only when legitimately established, otherwise "Unattributed telemetry source"
  target: string;
  service: string;
  source_location: string;
  latitude: number | null;
  longitude: number | null;
  mitre_technique: string;
  mitre_tactic: string;
  status: IncidentStatus;
  summary: string;
  evidence_count: number;
  detection_reason: string;
  is_lab_scenario: boolean;
  correlated_event_ids: string[];
}

export interface AgentRun {
  run_id: string;
  agent_id: 'monitor' | 'analyzer' | 'investigator' | 'threat_intel' | 'forensic' | 'guardian' | 'reporter';
  agent_name: string;
  incident_id: string;
  timestamp: string;
  task: string;
  input: string;
  output: string;
  decision: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'ABSTAINED' | 'FAILED';
  confidence: number;
}

export interface EvidenceRecord {
  evidence_id: string;
  incident_id: string;
  event_id: string;
  type: string;
  source: string;
  collected_timestamp: string;
  content: string;
  sha256: string;
  integrity_status: 'VALID' | 'INVALID' | 'UNVERIFIED';
  previous_evidence_hash: string | null;
  custody_chain: {
    collected_by: string;
    verified_by: string;
    timestamp: string;
  };
}

export interface SecurityUser {
  user_id: string;
  username: string;
  email: string;
  role: UserRole;
  password_hash: string;
  created_at: string;
  is_active: boolean;
  is_suspended: boolean;
  login_enabled: boolean;
  sessions_revoked_at: string | null;
  last_login: string | null;
  last_login_formatted_time?: string | null;
  last_ip: string | null;
  last_location: string | null;
  last_latitude?: number | null;
  last_longitude?: number | null;
  last_location_accuracy_meters?: number | null;
  last_device_info?: string | null;
}

export interface AuditLog {
  log_id: string;
  timestamp: string;
  actor_username: string;
  actor_role: string;
  action: string;
  target: string;
  details: string;
  ip_address: string;
  status: 'SUCCESS' | 'DENIED' | 'FAILED';
}

export interface ResponseAction {
  action_id: string;
  incident_id: string;
  action_type: 'ISOLATE_LAB_ENDPOINT' | 'BLOCK_LAB_SOURCE' | 'ESCALATE_TO_ANALYST' | 'PRESERVE_EVIDENCE' | 'SIMULATE_CONTAINMENT';
  executed_by: string;
  timestamp: string;
  status: 'PENDING' | 'EXECUTED' | 'ROLLED_BACK';
  notes: string;
}

export interface IntegrationStatus {
  name: string;
  category: string;
  status: 'CONNECTED' | 'DISCONNECTED' | 'UNAVAILABLE' | 'NOT CONFIGURED';
  details: string;
  version?: string;
  last_sync?: string;
}
