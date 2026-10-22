export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface UserSession {
  username: string;
  role: "ADMIN" | "ANALYST";
  token: string;
}

export interface AlertAIReport {
  probability?: string;
  analysis?: string;
  mitigations?: string[];
  firewall_cmd_windows?: string;
  firewall_cmd_linux?: string;
}

export interface AlertRecord {
  Timestamp: string;
  Type: string;
  "Source IP": string;
  Location: string;
  Details: string;
  "Log Line"?: string;
  ai_report?: AlertAIReport | string | null;
}

export interface BlockedIPRecord {
  ip: string;
  score: number;
  updated_at: string;
}

export interface IPReputationRecord {
  ip: string;
  score: number;
  blocked: number | boolean;
  updated_at: string;
}

export interface HealthResponse {
  status: string;
  ai_ready: boolean;
  active_brains: string[];
  signature_count: number;
}

export interface ConfusionMatrix {
  tn: number;
  fp: number;
  fn: number;
  tp: number;
}

export interface ModelMetricEntry {
  model_type: string;
  trained: boolean;
  trained_at: string | null;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  confusion_matrix: ConfusionMatrix;
  feature_importances: Record<string, number>;
}

export interface ModelAnalyticsResponse {
  brains_loaded: number;
  analytics: Record<string, ModelMetricEntry>;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactics?: string[];
  description?: string;
  platforms?: string[];
  url?: string;
  score?: number;
}

export interface MitreSearchResponse {
  query: string;
  total_techniques: number;
  results: MitreTechnique[];
}

export interface AgentStepResult {
  agent: string;
  model: string;
  status: "pending" | "running" | "done" | "error" | "intercepted";
  result: Record<string, unknown>;
  error: string;
  latency_ms: number;
}

export interface MultiAgentPipelineResult {
  pipeline_id: string;
  started_at: string;
  total_latency_ms: number;
  steps: AgentStepResult[];
  triage: {
    severity?: SeverityLevel;
    confidence?: number;
    attack_class?: string;
    attack_vector?: string;
    blast_radius?: string;
    summary?: string;
    affected_assets?: string[];
  };
  research: {
    attack_lifecycle_stage?: string;
    intelligence_summary?: string;
    threat_actor_context?: string;
    mitre_techniques?: MitreTechnique[];
    key_indicators?: string[];
  };
  remediation: {
    firewall_cmd_linux?: string;
    firewall_cmd_windows?: string;
    ansible_playbook?: string;
    sigma_rule?: string;
    patch_instructions?: string[];
  };
  guardrail: {
    final_verdict?: "APPROVED" | "INTERCEPTED" | "CORRECTED";
    risk_score?: number;
    verification_notes?: string;
  };
  approved: boolean;
  final_verdict: string;
}

export const SEVERITY_MAP: Record<string, SeverityLevel> = {
  "SQL Injection": "CRITICAL",
  "SQL Injection (Union)": "CRITICAL",
  "SQL Injection (Boolean)": "CRITICAL",
  "SQL Injection (Sleep/Time)": "CRITICAL",
  "XSS Attack": "HIGH",
  "XSS (Script Tag)": "MEDIUM",
  "XSS (Javascript)": "MEDIUM",
  "XSS (Event Handler)": "MEDIUM",
  "Path Traversal": "CRITICAL",
  "Directory Traversal (LFI)": "HIGH",
  "Password File Access": "HIGH",
  "Shadow File Access": "CRITICAL",
  "File Tampering": "CRITICAL",
  "Command Injection": "CRITICAL",
  "SSH Brute Force": "HIGH",
  "Invalid User Login": "MEDIUM",
  "Sudo Abuse": "HIGH",
  "Log4Shell Exploit": "CRITICAL",
  "Git Config Exposure": "HIGH",
  "Env File Exposure": "HIGH",
  "SSH Key Scan": "CRITICAL",
  "Nmap Scanner": "LOW",
  "Nikto Scanner": "MEDIUM",
  "Sqlmap Tool": "HIGH",
  "WordPress Login Bruteforce": "MEDIUM",
  "WordPress XMLRPC Attack": "MEDIUM",
  "PHP Info Leak": "LOW",
  "Remote File Inclusion (RFI)": "HIGH",
  "Null Byte Injection": "HIGH",
  "AWS Metadata Hack": "CRITICAL",
  "Shellshock Vulnerability": "CRITICAL",
  Masscan: "LOW",
  "Python Bot": "LOW",
  "Base64 Encoded Payload": "CRITICAL",
  "AI-WEB": "HIGH",
  "AI-AUTH": "HIGH",
  "AI-DOS": "CRITICAL",
  "AI-DDOS": "CRITICAL",
  "AI-RECON": "MEDIUM",
  "AI-BOTNET": "HIGH",
  "AI-INFILTRATION": "CRITICAL",
};

export function severityFor(type: string): SeverityLevel {
  return SEVERITY_MAP[type] || "MEDIUM";
}

export const SEVERITY_COLOR_HEX: Record<SeverityLevel, string> = {
  CRITICAL: "#ff1f5a",
  HIGH: "#ff9f0a",
  MEDIUM: "#ffd60a",
  LOW: "#10b981",
};
