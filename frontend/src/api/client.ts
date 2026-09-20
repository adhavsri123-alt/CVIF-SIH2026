/**
 * Centralized, typed API client for the CVIF REST API (Phase 10 / 11).
 * Completely air-gapped, using only native fetch() against the local CVIF API.
 */

import {
  ApiError,
  AssessRequest,
  AssuranceVerdict,
  AuditVerifyRequest,
  AuditVerifyResponse,
  DatasetIngestRequest,
  DatasetIngestResponse,
  DatasetScanRequest,
  DatasetScanResponse,
  DistributionShiftRequest,
  DistributionShiftResponse,
  EvidenceConsistencyResponse,
  EvidenceExportRequest,
  EvidenceExportResponse,
  EvidenceListResponse,
  EvidenceRecord,
  HealthStatusResponse,
  ModelSafetyScanRequest,
  ModelSafetyScanResponse,
  ModelScanRequest,
  ModelScanResponse,
  ProvenanceDemoRecordRequest,
  ProvenanceDemoRecordResponse,
  ProvenanceVerifyRequest,
  ProvenanceVerifyResponse,
  VersionResponse,
} from '../types/api';

class ApiClient {
  private baseUrl: string;
  private apiKey: string | null = null;

  constructor() {
    // Default to same-origin relative API path, or fallback to localhost in dev
    this.baseUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1';
    // Load from sessionStorage if previously set by user
    try {
      this.apiKey = sessionStorage.getItem('cvif_api_key');
    } catch {
      this.apiKey = null;
    }
  }

  public setApiKey(key: string | null): void {
    this.apiKey = key;
    try {
      if (key) {
        sessionStorage.setItem('cvif_api_key', key);
      } else {
        sessionStorage.removeItem('cvif_api_key');
      }
    } catch {
      // Ignore sessionStorage exceptions
    }
  }

  public getApiKey(): string | null {
    return this.apiKey;
  }

  public setBaseUrl(url: string): void {
    this.baseUrl = url;
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Request-ID': crypto.randomUUID ? crypto.randomUUID() : `req-${Date.now()}`,
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const config: RequestInit = {
      ...options,
      headers: {
        ...headers,
        ...(options.headers as Record<string, string>),
      },
    };

    let response: Response;
    try {
      response = await fetch(url, config);
    } catch (err: any) {
      throw {
        detail: `Network error connecting to CVIF API at ${url}. Ensure the server is running via 'cvif serve'.`,
        error_type: 'network_connection_failure',
        status_code: 0,
      } as ApiError;
    }

    const requestId = response.headers.get('X-Request-ID') || undefined;

    if (!response.ok) {
      let errorData: any = {};
      try {
        errorData = await response.json();
      } catch {
        errorData = { detail: response.statusText || 'Server Error' };
      }

      const apiError: ApiError = {
        detail: errorData.detail || errorData.message || 'An error occurred',
        error_type: errorData.error_type || errorData.error_code || `http_${response.status}`,
        request_id: errorData.request_id || requestId,
        status_code: response.status,
      };
      throw apiError;
    }

    return (await response.json()) as T;
  }

  // ── 1. System & Health ──────────────────────────────────────────────

  public async getHealth(): Promise<HealthStatusResponse> {
    return this.request<HealthStatusResponse>('/health', { method: 'GET' });
  }

  public async getVersion(): Promise<VersionResponse> {
    return this.request<VersionResponse>('/version', { method: 'GET' });
  }

  // ── 2. Audit Ledger ─────────────────────────────────────────────────

  public async verifyAudit(req: AuditVerifyRequest = {}): Promise<AuditVerifyResponse> {
    return this.request<AuditVerifyResponse>('/audit/verify', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  // ── 3. Datasets ─────────────────────────────────────────────────────

  public async ingestDataset(req: DatasetIngestRequest): Promise<DatasetIngestResponse> {
    return this.request<DatasetIngestResponse>('/datasets/ingest', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  public async scanDataset(req: DatasetScanRequest): Promise<DatasetScanResponse> {
    return this.request<DatasetScanResponse>('/datasets/scan', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  // ── 4. Models ───────────────────────────────────────────────────────

  public async scanModelSafety(req: ModelSafetyScanRequest): Promise<ModelSafetyScanResponse> {
    return this.request<ModelSafetyScanResponse>('/models/scan-safety', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  public async scanModel(req: ModelScanRequest): Promise<ModelScanResponse> {
    return this.request<ModelScanResponse>('/models/scan', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  // ── 5. Provenance ───────────────────────────────────────────────────

  public async verifyProvenance(req: ProvenanceVerifyRequest): Promise<ProvenanceVerifyResponse> {
    return this.request<ProvenanceVerifyResponse>('/provenance/verify', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  public async generateDemoProvenance(req?: ProvenanceDemoRecordRequest): Promise<ProvenanceDemoRecordResponse> {
    return this.request<ProvenanceDemoRecordResponse>('/provenance/demo-record', {
      method: 'POST',
      body: JSON.stringify(req || {}),
    });
  }

  // ── 6. Distribution Shift ───────────────────────────────────────────

  public async analyzeShift(req: DistributionShiftRequest): Promise<DistributionShiftResponse> {
    return this.request<DistributionShiftResponse>('/shift/analyze', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  // ── 7. Assurance Assessment ─────────────────────────────────────────

  public async assessSession(req: AssessRequest): Promise<AssuranceVerdict> {
    return this.request<AssuranceVerdict>('/assess', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  // ── 8. Evidence Store ───────────────────────────────────────────────

  public async listEvidence(params: {
    session_id?: string;
    finding_id?: string;
    threat_id?: string;
    evidence_type?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<EvidenceListResponse> {
    const query = new URLSearchParams();
    if (params.session_id) query.set('session_id', params.session_id);
    if (params.finding_id) query.set('finding_id', params.finding_id);
    if (params.threat_id) query.set('threat_id', params.threat_id);
    if (params.evidence_type) query.set('evidence_type', params.evidence_type);
    if (params.limit) query.set('limit', String(params.limit));
    if (params.offset) query.set('offset', String(params.offset));

    const qs = query.toString();
    const endpoint = `/evidence${qs ? `?${qs}` : ''}`;
    return this.request<EvidenceListResponse>(endpoint, { method: 'GET' });
  }

  public async getEvidence(id: string, verify: boolean = true): Promise<EvidenceRecord> {
    return this.request<EvidenceRecord>(`/evidence/${id}?verify=${verify}`, {
      method: 'GET',
    });
  }

  public async verifyEvidenceConsistency(sessionId?: string): Promise<EvidenceConsistencyResponse> {
    return this.request<EvidenceConsistencyResponse>('/evidence/verify', {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId }),
    });
  }

  public async exportEvidence(req: EvidenceExportRequest): Promise<EvidenceExportResponse> {
    return this.request<EvidenceExportResponse>('/evidence/export', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }
}

export const api = new ApiClient();
export default api;
