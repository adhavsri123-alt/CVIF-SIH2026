/**
 * Type-safe API interfaces for CVIF REST API (Phase 10 / Phase 11).
 * Directly synchronized with backend Pydantic models.
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type Disposition = 'ACCEPT' | 'REVIEW' | 'QUARANTINE';

export interface ApiError {
  detail: string;
  error_type: string;
  request_id?: string;
  status_code?: number;
}

// ── Health & System ───────────────────────────────────────────────────

export interface AuditArchiveInfo {
  present: boolean;
  verified: boolean;
  archive_file?: string | null;
  manifest_file?: string | null;
  expected_sha256?: string | null;
  actual_sha256?: string | null;
  total_events: number;
  documented_discontinuities: number;
  error_message?: string | null;
}

export interface AuditChainHealth {
  intact: boolean;
  broken_index?: number | null;
  total_events: number;
  verified_events: number;
  log_file: string;
  active_epoch?: number;
  archive?: AuditArchiveInfo | null;
}

export interface ServiceHealth {
  accessible: boolean;
  path?: string;
  directory?: string;
}

export interface HealthStatusResponse {
  status: 'HEALTHY' | 'DEGRADED';
  audit_chain: AuditChainHealth;
  database: ServiceHealth;
  evidence_store: ServiceHealth;
  truststore: ServiceHealth;
}

export interface VersionResponse {
  version: string;
  schema_version: string;
  architecture_version: string;
  python_version: string;
  platform: string;
  air_gap_enforced: boolean;
}

// ── Audit Ledger ──────────────────────────────────────────────────────

export interface AuditVerifyRequest {
  log_file?: string;
}

export interface AuditVerifyResponse {
  verified: boolean;
  broken_index?: number | null;
  total_events: number;
  verified_events: number;
  error_message?: string | null;
  log_file: string;
  status: string;
  active_epoch?: number;
  archive?: AuditArchiveInfo | null;
}

// ── Findings ──────────────────────────────────────────────────────────

export interface Finding {
  finding_id: string;
  asset_id: string;
  session_id: string;
  threat_id: string;
  category: string;
  severity: SeverityLevel;
  confidence: number;
  title: string;
  description: string;
  evidence_ids: string[];
  affected_assets: string[];
  recommended_disposition: Disposition;
  limitations: string[];
  timestamp: string;
  schema_version: string;
}

// ── Datasets ──────────────────────────────────────────────────────────

export interface DatasetIngestRequest {
  data_dir: string;
  format?: 'auto' | 'coco' | 'yolo';
  contributor_id?: string;
  batch_id?: string;
}

export interface DatasetIngestResponse {
  status: string;
  asset_id: string;
  contributor_id: string;
  format: string;
  image_count: number;
  annotation_count: number;
  total_size_bytes: number;
  validation: {
    is_valid: boolean;
    warnings: string[];
  };
}

export interface DatasetScanRequest {
  data_dir: string;
  session_id?: string;
  contributor_id?: string;
}

export interface DatasetScanResponse {
  session_id: string;
  asset_id: string;
  status: string;
  findings_count: number;
  has_critical_findings: boolean;
  findings: Finding[];
}

// ── Models ────────────────────────────────────────────────────────────

export interface ModelSafetyScanRequest {
  model_path: string;
}

export interface ModelSafetyScanResponse {
  model_path: string;
  is_safe: boolean;
  detected_format: string;
  file_hash: string;
  file_size_bytes: number;
  errors: string[];
  warnings: string[];
  status: string;
}

export interface ModelScanRequest {
  model_path: string;
  reference_weights?: string;
  session_id?: string;
}

export interface ModelScanResponse {
  session_id: string;
  asset_id: string;
  status: string;
  total_findings: number;
  has_critical_findings: boolean;
  executed_analyses: string[];
  findings: Finding[];
}

// ── Provenance ────────────────────────────────────────────────────────

export interface InferenceRecord {
  record_id: string;
  session_id: string;
  producer_id?: string;
  origin?: string;
  input_image_hash: string;
  model_id: string;
  model_weight_digest: string;
  preprocessing_config_hash: string;
  inference_config: Record<string, any>;
  output: Record<string, any>;
  binding_hmac?: string;
  signing_key_id?: string;
  timestamp: string;
  sequence_number: number;
  nonce: string;
  previous_record_hash?: string;
  signature?: string;
  schema_version?: string;
}

export interface ProvenanceVerifyRequest {
  record: InferenceRecord;
  raw_image_path?: string;
  expected_model_digest?: string;
  tolerance_seconds?: number;
  enforce_replay_checks?: boolean;
}

export interface ProvenanceVerifyResponse {
  record_id: string;
  session_id: string;
  contributor_id: string;
  status: string;
  is_valid: boolean;
  findings_count: number;
  findings: Finding[];
  details: Record<string, any>;
}

export interface ProvenanceDemoRecordRequest {
  session_id?: string;
  new_session?: boolean;
  tampered?: boolean;
}

export interface ProvenanceDemoRecordResponse {
  record: InferenceRecord;
  sequence_number: number;
  is_tampered: boolean;
  message: string;
}

// ── Distribution Shift ────────────────────────────────────────────────

export interface DistributionShiftRequest {
  reference_data: string;
  evaluation_data: string;
  session_id?: string;
}

export interface DimensionShiftInfo {
  dimension_name: string;
  shift_detected: boolean;
  p_value: number;
  statistic_value: number;
  threshold: number;
  details: Record<string, any>;
}

export interface DistributionShiftResponse {
  session_id: string;
  reference_asset_id: string;
  evaluation_asset_id: string;
  overall_shift_detected: boolean;
  dimensions: Record<string, DimensionShiftInfo>;
  findings_count: number;
  findings: Finding[];
  overall_distance?: number;
  natural_drift_likelihood?: number;
  suspicious_manipulation_likelihood?: number;
  characterization?: string;
}

// ── Assurance Assessment ──────────────────────────────────────────────

export interface AssessRequest {
  session_id: string;
}

export interface AssuranceVerdict {
  verdict_id: string;
  asset_id: string;
  session_id: string;
  composite_risk_score: number;
  disposition: Disposition;
  contributing_finding_ids: string[];
  summary: string;
  unsupported_checks: string[];
  timestamp: string;
  schema_version: string;
}

// ── Evidence Store ────────────────────────────────────────────────────

export interface ArtifactReference {
  path: string;
  media_type: string;
  description: string;
}

export interface EvidenceRecordSummary {
  evidence_id: string;
  session_id: string;
  finding_id?: string | null;
  evidence_type: string;
  content_hash: string;
  created_at: string;
  threat_id?: string | null;
}

export interface EvidenceListResponse {
  total: number;
  records: EvidenceRecordSummary[];
}

export interface EvidenceRecord {
  evidence_id: string;
  finding_id: string;
  session_id: string;
  evidence_type: string;
  metrics?: Record<string, number> | null;
  artifacts?: ArtifactReference[] | null;
  baseline_comparison?: Record<string, any> | null;
  raw_data_ref?: string | null;
  narrative: string;
  methodology: string;
  reproducibility_info?: Record<string, any>;
  timestamp: string;
  schema_version: string;
  content_hash?: string;
  threat_id?: string | null;
}

export interface EvidenceVerifyRequest {
  session_id?: string;
}

export interface EvidenceConsistencyResponse {
  total_records: number;
  total_artifacts: number;
  is_consistent: boolean;
  missing_records: string[];
  tampered_records: string[];
  missing_artifacts: string[];
  tampered_artifacts: string[];
}

export interface EvidenceExportRequest {
  session_id: string;
  output_path?: string;
}

export interface EvidenceExportResponse {
  session_id: string;
  archive_path: string;
  total_records: number;
  total_files: number;
  sha256_manifest_digest: string;
}

// ── Integrity Lineage ───────────────────────────────────────────────────

export type LineageStageStatus =
  | 'VERIFIED'
  | 'FINDINGS'
  | 'REVIEW'
  | 'UNSUPPORTED'
  | 'NOT RUN'
  | 'FAILED / TAMPERED';

export type OverallLineageStatus =
  | 'VERIFIED'
  | 'FINDINGS / REVIEW'
  | 'FAILED / QUARANTINE'
  | 'INCOMPLETE / NOT VERIFIED'
  | 'LIMITED COVERAGE';

export interface UnsupportedCheckDetail {
  check_id: string;
  reason: string;
}

export interface DatasetLineageNode {
  stage: string;
  status: LineageStageStatus;
  dataset_identity?: string | null;
  dataset_hash?: string | null;
  format?: string | null;
  findings_count: number;
  findings: Finding[];
  evidence_count: number;
  details: Record<string, any>;
}

export interface ModelLineageNode {
  stage: string;
  status: LineageStageStatus;
  candidate_model_id?: string | null;
  model_digest?: string | null;
  reference_model?: string | null;
  findings_count: number;
  findings: Finding[];
  supported_checks: string[];
  unsupported_checks: UnsupportedCheckDetail[];
  details: Record<string, any>;
}

export interface InferenceLineageNode {
  stage: string;
  status: LineageStageStatus;
  record_id?: string | null;
  session_id?: string | null;
  bound_model_digest?: string | null;
  verification_state: string;
  is_valid: boolean;
  is_tampered: boolean;
  is_replayed: boolean;
  model_mismatch: boolean;
  producer_id?: string | null;
  signing_key_id?: string | null;
  findings_count: number;
  findings: Finding[];
  details: Record<string, any>;
}

export interface DistributionLineageNode {
  stage: string;
  status: LineageStageStatus;
  executed: boolean;
  overall_distance?: number | null;
  natural_drift_likelihood?: number | null;
  suspicious_manipulation_likelihood?: number | null;
  shift_detected: boolean;
  dimension_results: Record<string, any>;
  characterization?: string | null;
  details: Record<string, any>;
}

export interface EvidenceLineageNode {
  stage: string;
  status: LineageStageStatus;
  total_records: number;
  cryptographic_records: number;
  statistical_records: number;
  artifact_records: number;
  records: EvidenceRecordSummary[];
  details: Record<string, any>;
}

export interface AuditLineageNode {
  stage: string;
  status: LineageStageStatus;
  active_epoch: number;
  chain_intact: boolean;
  total_events: number;
  verified_events: number;
  error_message?: string | null;
  details: Record<string, any>;
}

export interface AssuranceLineageNode {
  stage: string;
  status: LineageStageStatus;
  assessed: boolean;
  disposition?: Disposition | null;
  composite_risk_score?: number | null;
  summary?: string | null;
  coverage_state: string;
  contributing_finding_ids: string[];
  unsupported_checks: string[];
  details: Record<string, any>;
}

export interface LineageDependency {
  source: string;
  target: string;
  relationship: string;
  is_valid: boolean;
  description: string;
}

export interface IntegrityLineageResponse {
  session_id: string;
  overall_status: OverallLineageStatus;
  summary: string;
  dataset: DatasetLineageNode;
  model: ModelLineageNode;
  inference: InferenceLineageNode;
  distribution: DistributionLineageNode;
  evidence: EvidenceLineageNode;
  audit: AuditLineageNode;
  assurance: AssuranceLineageNode;
  dependencies: LineageDependency[];
  timestamp: string;
}

export interface LineageVerifyRequest {
  session_id: string;
}

// ── Session Management ──────────────────────────────────────────────────

export interface CreateSessionRequest {
  operator_id?: string;
}

export interface CreateSessionResponse {
  session_id: string;
  status: string;
  created_at: string;
}
