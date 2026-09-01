// Shared API response types (prompt 22). These mirror the backend JSON contracts;
// the backend remains authoritative. Types are intentionally permissive where the
// backend payload is broad — the UI never invents fields.

export interface AnalysisListItem {
  id: string;
  apk_id: string;
  profile: string;
  status: string;
  apk_sha256: string;
  started_at: string | null;
  package: string | null;
  finding_count: number;
  native_library_count: number;
}

export interface Provenance {
  source_type?: string | null;
  source_artifact?: string | null;
  file_path?: string | null;
  source_line?: number | null;
  location?: string | null;
  evidence_id?: string | null;
  confidence?: string | null;
  timestamp?: string | null;
}

export interface Evidence {
  source?: string | null;
  source_type?: string | null;
  source_id?: string | null;
  location?: string | null;
  detail?: string | null;
  artifact?: string | null;
  file?: string | null;
  class?: string | null;
  method?: string | null;
  line?: number | null;
  confidence?: string | null;
  timestamp?: string | null;
  evidence_id?: string | null;
  mode?: string | null; // LIVE | MOCKED
  uncertainty?: string | string[] | null;
}

export interface Finding {
  id: string;
  fingerprint?: string | null;
  rule_id: string;
  title: string;
  category: string;
  severity: string;
  severity_score?: number | null;
  confidence: string;
  confidence_score?: number | null;
  status: string;
  component?: string | null;
  root_cause_id?: string | null;
  runtime_status?: string | null;
  runtime_validation_state: string;
  evidence_count: number;
  description?: string | null;
  remediation?: string | null;
  references?: unknown;
  validation?: { state: string; confidence: number; claim_count: number; evidence_count: number; blocker_count: number; summary?: string | null };
  evidence: Evidence[];
}

export interface AnalysisReport {
  schema?: string;
  analysis: { id: string; profile: string; status: string; ruleset_version?: string; started_at?: string; completed_at?: string; stages?: any[] };
  apk: { id: string; original_filename?: string; sha256: string; size_bytes?: number; package_name?: string | null; version_name?: string | null; version_code?: string | null };
  capabilities: Record<string, string>;
  manifest?: Record<string, any> | null;
  summary?: Record<string, any>;
  risk?: any;
  root_causes?: any[];
  knowledge_graph?: { digest?: string; node_count?: number; edge_count?: number; truncated?: boolean; version?: string };
  runtime_summary?: { mode?: string; sessions?: number; observations?: number };
  [k: string]: any;
}

export interface Capability {
  name: string;
  availability: string;
  version?: string | null;
  path?: string | null;
  reason?: string;
}

export interface DoctorReport {
  platform: string;
  tools: Array<Record<string, any>>;
  runtime?: Capability[];
  graph?: Capability[];
  intelligence?: any;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  analysis_id?: string;
  confidence?: string;
  status?: string | null;
  provenance?: Provenance[];
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  confidence?: string;
  provenance?: Provenance[];
  evidence_refs?: string[];
}

export interface KnowledgeGraph {
  analysis_id: string;
  graph_version?: string;
  digest: string;
  truncated: boolean;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ValidationClaim {
  id: string;
  claim_type: string;
  target_type: string;
  target: string;
  validation_state: string;
  confidence: number;
  evidence_count: number;
  independent_source_count: number;
  source_families?: string[];
  finding_id?: string | null;
  required_capabilities?: string[];
  blockers?: Array<{ blocker: string; reason?: string; missing?: string }>;
  requirements?: Array<{ requirement: string; satisfied: boolean; hard?: boolean }>;
  uncertainty?: string[];
  evidence?: Evidence[];
}

export interface RuntimeCorrelation {
  id: string;
  subject_type: string;
  subject_ref: string;
  correlation_type: string;
  taxonomy?: string | null;
  mode: string; // LIVE | MOCKED
  confidence: string;
  provenance: string;
  detail: string;
}

export interface RuntimeValidationView {
  mode: string;
  fingerprint: string;
  device_serial?: string | null;
  apk_sha256?: string | null;
  summary: Record<string, any>;
  correlations: RuntimeCorrelation[];
  blockers: Array<{ blocker: string; reason?: string }>;
  truncated: Record<string, any> | any[];
  uncertainties: string[];
  provenance: string[];
  note: string;
  device_identity?: Record<string, any>;
  runtime_finding_states?: Record<string, number>;
  corroborated_findings?: string[];
}

export interface RemediationItem {
  id: string;
  status: string;
  priority: string;
  priority_score: number;
  action: string;
  fixability: string;
  title: string;
  description?: string;
  target?: string | null;
  target_type?: string;
  current_state?: string | null;
  recommended_state?: string | null;
  confidence: string;
  source_category?: string;
  evidence?: Evidence[];
  priority_factors?: Array<{ name: string; weight: number; reason: string }>;
  uncertainties?: string[];
}

export interface Comparison {
  id?: string;
  summary?: Record<string, any>;
  [k: string]: any;
}
