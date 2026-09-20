import React, { useState, useEffect } from 'react';
import {
  EvidenceRecordSummary,
  EvidenceRecord,
  EvidenceConsistencyResponse,
  EvidenceExportResponse,
  ApiError,
} from '../types/api';
import api from '../api/client';
import {
  FileCheck2,
  ShieldCheck,
  ShieldAlert,
  Download,
  AlertOctagon,
  Eye,
  X,
  Filter,
  RotateCcw,
  Copy,
  Check,
  FileCode,
  Layers,
  Activity,
} from 'lucide-react';

interface EvidencePageProps {
  activeSessionId: string;
}

export const EvidencePage: React.FC<EvidencePageProps> = ({ activeSessionId }) => {
  const [records, setRecords] = useState<EvidenceRecordSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  // Filters
  const [sessionFilter, setSessionFilter] = useState(activeSessionId || '');
  const [threatFilter, setThreatFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  // Selected Detail Drawer
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<EvidenceRecord | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [recordError, setRecordError] = useState<ApiError | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Consistency audit
  const [consistencyResult, setConsistencyResult] = useState<EvidenceConsistencyResponse | null>(null);
  const [consistencyLoading, setConsistencyLoading] = useState(false);

  // Export
  const [exportResult, setExportResult] = useState<EvidenceExportResponse | null>(null);
  const [exportLoading, setExportLoading] = useState(false);

  // Sync if activeSessionId changes in top bar
  useEffect(() => {
    if (activeSessionId) {
      setSessionFilter(activeSessionId);
    }
  }, [activeSessionId]);

  // Query evidence whenever filters change
  useEffect(() => {
    const timer = setTimeout(() => {
      loadEvidence();
    }, 200);
    return () => clearTimeout(timer);
  }, [sessionFilter, threatFilter, typeFilter]);

  const loadEvidence = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listEvidence({
        session_id: sessionFilter.trim() || undefined,
        threat_id: threatFilter.trim() || undefined,
        evidence_type: typeFilter.trim() || undefined,
        limit: 100,
      });
      setRecords(res.records);
      setTotal(res.total);
    } catch (err: any) {
      setError(err as ApiError);
      setRecords([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  const handleResetFilters = () => {
    setSessionFilter('');
    setThreatFilter('');
    setTypeFilter('');
  };

  const handleSelectRecord = async (id: string) => {
    setSelectedId(id);
    setSelectedRecord(null);
    setRecordError(null);
    setDetailLoading(true);
    try {
      const rec = await api.getEvidence(id, true);
      const summary = records.find((r) => r.evidence_id === id);
      setSelectedRecord({
        ...rec,
        content_hash: summary?.content_hash,
        threat_id: summary?.threat_id || rec.reproducibility_info?.threat_id,
      });
    } catch (err: any) {
      setRecordError(err as ApiError);
      setSelectedRecord(null);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleVerifyConsistency = async () => {
    setConsistencyLoading(true);
    setError(null);
    try {
      const res = await api.verifyEvidenceConsistency(sessionFilter.trim() || undefined);
      setConsistencyResult(res);
    } catch (err: any) {
      setError(err as ApiError);
    } finally {
      setConsistencyLoading(false);
    }
  };

  const handleExport = async () => {
    if (!sessionFilter.trim()) {
      alert('Please specify a Session UUID in the session filter to export evidence.');
      return;
    }

    setExportLoading(true);
    setError(null);
    try {
      const res = await api.exportEvidence({
        session_id: sessionFilter.trim(),
      });
      setExportResult(res);
    } catch (err: any) {
      setError(err as ApiError);
    } finally {
      setExportLoading(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const hasActiveFilters = Boolean(sessionFilter || threatFilter || typeFilter);

  return (
    <div className="page-container">
      <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1>Immutable Evidence Store Explorer</h1>
          <p>
            Cryptographically indexed, write-once evidence records ensuring chain of custody and forensic verifiability.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            className="btn btn-secondary"
            onClick={handleVerifyConsistency}
            disabled={consistencyLoading}
            id="btn-verify-store"
          >
            <ShieldCheck size={16} />
            {consistencyLoading ? 'Auditing Digests...' : 'Verify Store Integrity'}
          </button>

          <button
            className="btn btn-primary"
            onClick={handleExport}
            disabled={exportLoading || !sessionFilter.trim()}
            id="btn-export-bundle"
            title={!sessionFilter.trim() ? 'Filter by a specific Session UUID to export' : 'Export Session Evidence Bundle'}
          >
            <Download size={16} />
            {exportLoading ? 'Packaging .cvif...' : 'Export Session Bundle'}
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertOctagon size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Evidence Error [{error.error_type}]</strong>: {error.detail}
            {error.request_id && (
              <div style={{ fontSize: '0.8rem', marginTop: '4px' }}>
                Request-ID: <code className="font-mono">{error.request_id}</code>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Consistency Audit Alert */}
      {consistencyResult && (
        <div
          className={`alert ${consistencyResult.is_consistent ? 'alert-info' : 'alert-danger'}`}
        >
          {consistencyResult.is_consistent ? (
            <ShieldCheck size={18} style={{ color: '#10b981' }} />
          ) : (
            <ShieldAlert size={18} style={{ color: '#ef4444' }} />
          )}
          <div>
            <strong>
              Store Consistency Audit: {consistencyResult.is_consistent ? 'VERIFIED INTACT' : 'TAMPERING DETECTED'}
            </strong>
            <div style={{ fontSize: '0.8rem', marginTop: '4px' }}>
              Checked {consistencyResult.total_records} records and {consistencyResult.total_artifacts} physical artifacts.
              {consistencyResult.tampered_records.length > 0 && (
                <div style={{ color: '#ef4444' }}>
                  Tampered records: {consistencyResult.tampered_records.join(', ')}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Export Result Card */}
      {exportResult && (
        <div className="alert alert-info">
          <Download size={18} style={{ color: '#3b82f6' }} />
          <div>
            <strong>Evidence Bundle Exported Successfully</strong>
            <div style={{ fontSize: '0.8rem', marginTop: '4px' }}>
              Archive Path: <code className="font-mono">{exportResult.archive_path}</code> ({exportResult.total_files} files)
              <br />
              SHA-256 Manifest Digest: <code className="font-mono">{exportResult.sha256_manifest_digest}</code>
            </div>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="card" style={{ padding: '14px 20px', marginBottom: '16px' }}>
        <div style={{ display: 'flex', gap: '14px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted)' }}>
            <Filter size={16} /> Filters:
          </div>

          <div style={{ flex: 1, minWidth: '220px' }}>
            <input
              type="text"
              id="filter-session"
              className="form-input font-mono"
              style={{ fontSize: '0.8rem' }}
              value={sessionFilter}
              onChange={(e) => setSessionFilter(e.target.value)}
              placeholder="Filter by Session UUID or prefix..."
            />
          </div>

          <div style={{ width: '160px' }}>
            <input
              type="text"
              id="filter-threat"
              className="form-input font-mono"
              style={{ fontSize: '0.8rem' }}
              value={threatFilter}
              onChange={(e) => setThreatFilter(e.target.value)}
              placeholder="Threat ID (e.g. DT-1)"
            />
          </div>

          <div style={{ width: '170px' }}>
            <input
              type="text"
              id="filter-type"
              className="form-input"
              style={{ fontSize: '0.8rem' }}
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              placeholder="Evidence Type..."
            />
          </div>

          {hasActiveFilters && (
            <button
              id="btn-reset-filters"
              className="btn btn-secondary"
              style={{ padding: '6px 12px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
              onClick={handleResetFilters}
              title="Reset all filters to default"
            >
              <RotateCcw size={14} /> Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Evidence Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <FileCheck2 size={18} style={{ color: '#3b82f6' }} />
            Indexed Evidence Records ({total} total)
          </div>
          {loading && (
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Refreshing metadata...
            </span>
          )}
        </div>

        {records.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '36px 16px' }}>
            <p style={{ color: 'var(--text-muted)', marginBottom: '16px' }}>
              {loading ? 'Querying metadata catalog...' : 'No evidence records match active filter criteria.'}
            </p>
            {hasActiveFilters && !loading && (
              <button
                className="btn btn-secondary"
                style={{ fontSize: '0.8rem', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                onClick={handleResetFilters}
              >
                <RotateCcw size={14} /> Clear Active Filters
              </button>
            )}
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Evidence UUID</th>
                  <th>Threat</th>
                  <th>Type</th>
                  <th>Session Context</th>
                  <th>Content SHA-256 Digest</th>
                  <th>Created At</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.evidence_id}>
                    <td className="font-mono" style={{ fontWeight: 600 }}>
                      <span title={r.evidence_id}>{r.evidence_id.substring(0, 8)}...</span>
                    </td>
                    <td>
                      {r.threat_id ? (
                        <span className="badge" style={{ backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.3)', fontFamily: 'var(--font-mono)' }}>
                          {r.threat_id}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>—</span>
                      )}
                    </td>
                    <td>
                      <span className="badge badge-info">{r.evidence_type}</span>
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.8rem' }}>
                      <span title={r.session_id}>{r.session_id.substring(0, 8)}...</span>
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.8rem' }}>
                      <span title={r.content_hash}>{r.content_hash.substring(0, 16)}...</span>
                    </td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {new Date(r.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}{' '}
                      <span style={{ fontSize: '0.7rem' }}>{r.created_at.split('T')[0]}</span>
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '4px 10px', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '4px' }}
                        onClick={() => handleSelectRecord(r.evidence_id)}
                        id={`btn-inspect-${r.evidence_id.substring(0, 8)}`}
                      >
                        <Eye size={12} /> Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Slide-out Record Detail Drawer */}
      {selectedId && (
        <div className="drawer-backdrop" onClick={() => setSelectedId(null)}>
          <div className="drawer-panel" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '680px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <ShieldCheck size={22} style={{ color: '#10b981' }} />
                <div>
                  <h3 style={{ margin: 0 }}>Evidence Record Detail</h3>
                  {selectedRecord?.threat_id && (
                    <span className="badge" style={{ backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.3)', marginTop: '4px', display: 'inline-block' }}>
                      Threat: {selectedRecord.threat_id}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={() => setSelectedId(null)}
                style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer', padding: '4px' }}
                title="Close drawer"
                id="btn-close-drawer"
              >
                <X size={20} />
              </button>
            </div>

            {detailLoading ? (
              <div style={{ padding: '32px 0', textAlign: 'center' }}>
                <p style={{ color: 'var(--text-muted)' }}>Verifying SHA-256 cryptographic digest & retrieving record...</p>
              </div>
            ) : recordError ? (
              <div className="alert alert-danger">
                <AlertOctagon size={18} style={{ flexShrink: 0 }} />
                <div>
                  <strong>Failed to Load Record [{recordError.error_type}]</strong>
                  <p style={{ margin: '4px 0 0 0', fontSize: '0.85rem' }}>{recordError.detail}</p>
                </div>
              </div>
            ) : selectedRecord ? (
              <div>
                {/* Forensic Metadata Box */}
                <div style={{ backgroundColor: 'var(--bg-primary)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginBottom: '20px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px', fontSize: '0.85rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Record UUID:</span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <code className="font-mono">{selectedRecord.evidence_id}</code>
                        <button
                          style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer' }}
                          onClick={() => copyToClipboard(selectedRecord.evidence_id, 'evidence_id')}
                          title="Copy UUID"
                        >
                          {copiedKey === 'evidence_id' ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                        </button>
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Type:</span>
                      <span className="badge badge-info">{selectedRecord.evidence_type}</span>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Session UUID:</span>
                      <code className="font-mono" style={{ fontSize: '0.8rem' }}>{selectedRecord.session_id}</code>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Parent Finding UUID:</span>
                      <code className="font-mono" style={{ fontSize: '0.8rem' }}>{selectedRecord.finding_id || 'None'}</code>
                    </div>

                    {selectedRecord.content_hash && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '4px', borderTop: '1px solid var(--border-subtle)' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Verified Content Digest:</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <code className="font-mono" style={{ color: '#10b981', fontSize: '0.78rem' }}>
                            {selectedRecord.content_hash}
                          </code>
                          <button
                            style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer' }}
                            onClick={() => copyToClipboard(selectedRecord.content_hash!, 'content_hash')}
                            title="Copy SHA-256 digest"
                          >
                            {copiedKey === 'content_hash' ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                          </button>
                        </div>
                      </div>
                    )}

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Recorded Timestamp:</span>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{selectedRecord.timestamp}</span>
                    </div>
                  </div>
                </div>

                {/* Narrative Section */}
                <div style={{ marginBottom: '20px' }}>
                  <h4 style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                    <Activity size={16} style={{ color: '#3b82f6' }} /> Forensic Narrative
                  </h4>
                  <div
                    style={{
                      backgroundColor: 'rgba(59, 130, 246, 0.08)',
                      border: '1px solid rgba(59, 130, 246, 0.25)',
                      padding: '12px 16px',
                      borderRadius: '6px',
                      fontSize: '0.9rem',
                      lineHeight: '1.5',
                      color: 'var(--text-primary)',
                    }}
                  >
                    {selectedRecord.narrative}
                  </div>
                </div>

                {/* Methodology */}
                <div style={{ marginBottom: '20px' }}>
                  <h4 style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                    <Layers size={16} style={{ color: '#8b5cf6' }} /> Algorithmic Methodology
                  </h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>
                    {selectedRecord.methodology}
                  </p>
                </div>

                {/* Quantitative Metrics */}
                {selectedRecord.metrics && Object.keys(selectedRecord.metrics).length > 0 && (
                  <div style={{ marginBottom: '20px' }}>
                    <h4 style={{ marginBottom: '8px' }}>Quantitative Statistical Metrics</h4>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
                      {Object.entries(selectedRecord.metrics).map(([k, v]) => (
                        <div
                          key={k}
                          style={{
                            backgroundColor: 'var(--bg-primary)',
                            padding: '8px 12px',
                            borderRadius: '6px',
                            border: '1px solid var(--border-subtle)',
                          }}
                        >
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{k}</div>
                          <div className="font-mono" style={{ fontSize: '1rem', fontWeight: 600, color: '#60a5fa' }}>
                            {typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(4)) : String(v)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Reproducibility Info */}
                {selectedRecord.reproducibility_info && Object.keys(selectedRecord.reproducibility_info).length > 0 && (
                  <div style={{ marginBottom: '20px' }}>
                    <h4 style={{ marginBottom: '8px' }}>Reproducibility Parameters</h4>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                      {Object.entries(selectedRecord.reproducibility_info).map(([k, v]) => (
                        <span
                          key={k}
                          className="font-mono"
                          style={{
                            fontSize: '0.78rem',
                            backgroundColor: 'var(--bg-primary)',
                            padding: '4px 8px',
                            borderRadius: '4px',
                            border: '1px solid var(--border-subtle)',
                          }}
                        >
                          <span style={{ color: 'var(--text-muted)' }}>{k}:</span> {String(v)}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Linked Diagnostic Artifacts */}
                <div style={{ marginBottom: '20px' }}>
                  <h4 style={{ marginBottom: '8px' }}>
                    Linked Diagnostic Artifacts ({selectedRecord.artifacts ? selectedRecord.artifacts.length : 0})
                  </h4>
                  {!selectedRecord.artifacts || selectedRecord.artifacts.length === 0 ? (
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0 }}>
                      No separate physical artifact files attached.
                    </p>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {selectedRecord.artifacts.map((art, idx) => (
                        <div
                          key={idx}
                          style={{
                            backgroundColor: 'var(--bg-primary)',
                            padding: '10px 12px',
                            borderRadius: '6px',
                            border: '1px solid var(--border-subtle)',
                            fontSize: '0.8rem',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                            <code className="font-mono" style={{ color: '#60a5fa' }}>{art.path}</code>
                            <span className="badge badge-info">{art.media_type}</span>
                          </div>
                          {art.description && (
                            <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
                              {art.description}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Canonical Data Payload Viewer */}
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <h4 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <FileCode size={16} /> Canonical Record JSON
                    </h4>
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '3px 8px', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '4px' }}
                      onClick={() => copyToClipboard(JSON.stringify(selectedRecord, null, 2), 'payload')}
                    >
                      {copiedKey === 'payload' ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                      {copiedKey === 'payload' ? 'Copied' : 'Copy JSON'}
                    </button>
                  </div>
                  <pre
                    className="font-mono"
                    style={{
                      backgroundColor: 'var(--bg-primary)',
                      padding: '12px',
                      borderRadius: '6px',
                      border: '1px solid var(--border-subtle)',
                      fontSize: '0.75rem',
                      overflowX: 'auto',
                      maxHeight: '260px',
                    }}
                  >
                    {JSON.stringify(selectedRecord, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <p style={{ color: '#ef4444' }}>Unable to load evidence record detail.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

