import React, { useState, useEffect } from 'react';
import {
  IntegrityLineageResponse,
  LineageStageStatus,
  OverallLineageStatus,
  ApiError,
} from '../types/api';
import api from '../api/client';
import { SeverityBadge, DispositionBadge } from '../components/common/Badges';
import {
  GitFork,
  Database,
  Cpu,
  FileKey,
  Activity,
  FileCheck2,
  Lock,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ArrowDown,
  ExternalLink,
  RefreshCw,
  AlertOctagon,
  Copy,
  Check,
} from 'lucide-react';

interface LineagePageProps {
  activeSessionId: string;
  onNavigate: (tab: string) => void;
}

export const LineagePage: React.FC<LineagePageProps> = ({
  activeSessionId,
  onNavigate,
}) => {
  const [lineage, setLineage] = useState<IntegrityLineageResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  useEffect(() => {
    if (activeSessionId) {
      loadLineage(activeSessionId);
    } else {
      setLineage(null);
      setError(null);
    }
  }, [activeSessionId]);

  const loadLineage = async (sessionId: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getLineage(sessionId);
      setLineage(data);
    } catch (err: any) {
      const apiErr = err as ApiError;
      setError(apiErr.detail || 'Failed to load integrity lineage for active session.');
      setLineage(null);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyLineage = async () => {
    if (!activeSessionId) return;
    setVerifying(true);
    setError(null);
    try {
      const data = await api.verifyLineage(activeSessionId);
      setLineage(data);
    } catch (err: any) {
      const apiErr = err as ApiError;
      setError(apiErr.detail || 'Lineage verification failed.');
    } finally {
      setVerifying(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const renderStageBadge = (status: LineageStageStatus) => {
    switch (status) {
      case 'VERIFIED':
        return (
          <span className="badge badge-accept">
            <CheckCircle2 size={12} /> VERIFIED
          </span>
        );
      case 'FINDINGS':
        return (
          <span className="badge badge-medium">
            <AlertTriangle size={12} /> FINDINGS
          </span>
        );
      case 'REVIEW':
        return (
          <span className="badge badge-review">
            <AlertTriangle size={12} /> REVIEW
          </span>
        );
      case 'UNSUPPORTED':
        return (
          <span className="badge badge-info">
            <HelpCircle size={12} /> UNSUPPORTED
          </span>
        );
      case 'NOT RUN':
        return (
          <span className="badge badge-info" style={{ opacity: 0.75 }}>
            <HelpCircle size={12} /> NOT RUN
          </span>
        );
      case 'FAILED / TAMPERED':
        return (
          <span className="badge badge-quarantine">
            <ShieldAlert size={12} /> FAILED / TAMPERED
          </span>
        );
      default:
        return <span className="badge badge-info">{status}</span>;
    }
  };

  const renderOverallBadge = (status: OverallLineageStatus) => {
    switch (status) {
      case 'VERIFIED':
        return (
          <span className="badge badge-accept" style={{ fontSize: '0.875rem', padding: '6px 12px' }}>
            <ShieldCheck size={16} /> VERIFIED
          </span>
        );
      case 'FINDINGS / REVIEW':
        return (
          <span className="badge badge-review" style={{ fontSize: '0.875rem', padding: '6px 12px' }}>
            <AlertTriangle size={16} /> FINDINGS / REVIEW
          </span>
        );
      case 'FAILED / QUARANTINE':
        return (
          <span className="badge badge-quarantine" style={{ fontSize: '0.875rem', padding: '6px 12px' }}>
            <ShieldAlert size={16} /> FAILED / QUARANTINE
          </span>
        );
      case 'LIMITED COVERAGE':
        return (
          <span className="badge badge-medium" style={{ fontSize: '0.875rem', padding: '6px 12px' }}>
            <HelpCircle size={16} /> LIMITED COVERAGE
          </span>
        );
      case 'INCOMPLETE / NOT VERIFIED':
      default:
        return (
          <span className="badge badge-info" style={{ fontSize: '0.875rem', padding: '6px 12px' }}>
            <HelpCircle size={16} /> INCOMPLETE / NOT VERIFIED
          </span>
        );
    }
  };

  return (
    <div className="page-container">
      {/* Page Title & Context */}
      <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <GitFork size={26} color="#3b82f6" />
            Integrity Lineage
          </h1>
          <p style={{ margin: '4px 0 0 0', color: 'var(--text-muted)' }}>
            Trace and cryptographically verify the end-to-end chain of custody across the computer-vision pipeline.
          </p>
        </div>

        {activeSessionId && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              className="btn btn-secondary"
              onClick={() => loadLineage(activeSessionId)}
              disabled={loading || verifying}
              title="Refresh Lineage"
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>

            <button
              className="btn btn-primary"
              onClick={handleVerifyLineage}
              disabled={loading || verifying}
              id="verify-lineage-btn"
            >
              <ShieldCheck size={16} />
              <span>{verifying ? 'Verifying...' : 'Verify Lineage'}</span>
            </button>
          </div>
        )}
      </div>

      {/* Error Banner */}
      {error && (
        <div className="alert alert-danger" style={{ marginBottom: '20px' }}>
          <AlertOctagon size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Lineage Query Error</strong>: {error}
          </div>
        </div>
      )}

      {/* Empty State: NO ACTIVE SESSION */}
      {!activeSessionId && (
        <div className="card" style={{ padding: '48px 24px', textAlign: 'center' }}>
          <div
            style={{
              width: '64px',
              height: '64px',
              borderRadius: '50%',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#3b82f6',
              marginBottom: '16px',
            }}
          >
            <GitFork size={32} />
          </div>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '8px' }}>NO ACTIVE SESSION</h2>
          <p
            style={{
              color: 'var(--text-muted)',
              maxWidth: '560px',
              margin: '0 auto 24px auto',
              lineHeight: 1.5,
              fontSize: '0.9rem',
            }}
          >
            No active analysis session selected. To trace and verify integrity lineage across Dataset, Model, Inference, Distribution, Evidence, Audit, and Assurance, please select an existing session from the top bar or run an analysis in Dataset Integrity or Model Integrity to create a new session.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '12px' }}>
            <button className="btn btn-primary" onClick={() => onNavigate('dataset')}>
              <Database size={16} />
              <span>Go to Dataset Integrity</span>
            </button>
            <button className="btn btn-secondary" onClick={() => onNavigate('model')}>
              <Cpu size={16} />
              <span>Go to Model Integrity</span>
            </button>
          </div>
        </div>
      )}

      {/* Populated Lineage Content */}
      {activeSessionId && lineage && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Overall Lineage Summary Card */}
          <div className="card" style={{ borderLeft: lineage.overall_status === 'VERIFIED' ? '4px solid #10b981' : lineage.overall_status === 'FAILED / QUARANTINE' ? '4px solid #ef4444' : '4px solid #f59e0b' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Pipeline Integrity Lineage Verdict
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '6px' }}>
                  <h2 style={{ margin: 0, fontSize: '1.4rem' }}>Lineage Status</h2>
                  {renderOverallBadge(lineage.overall_status)}
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-muted)', backgroundColor: 'var(--bg-tertiary)', padding: '6px 12px', borderRadius: '4px' }}>
                <span>Session:</span>
                <code className="font-mono" style={{ color: 'var(--text-primary)' }}>{lineage.session_id}</code>
                <button
                  onClick={() => handleCopy(lineage.session_id)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', color: 'var(--text-muted)' }}
                  title="Copy session ID"
                >
                  {copiedText === lineage.session_id ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                </button>
              </div>
            </div>

            <p style={{ margin: '0 0 16px 0', fontSize: '0.95rem', lineHeight: 1.5 }}>
              {lineage.summary}
            </p>

            {/* Metric Summary Bar */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Dataset Status</span>
                <div style={{ marginTop: '4px' }}>{renderStageBadge(lineage.dataset.status)}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Model Integrity</span>
                <div style={{ marginTop: '4px' }}>{renderStageBadge(lineage.model.status)}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Inference Provenance</span>
                <div style={{ marginTop: '4px' }}>{renderStageBadge(lineage.inference.status)}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Distribution Shift</span>
                <div style={{ marginTop: '4px' }}>{renderStageBadge(lineage.distribution.status)}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Forensic Evidence</span>
                <div style={{ marginTop: '4px', fontWeight: 600 }}>{lineage.evidence.total_records} records</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Audit Ledger</span>
                <div style={{ marginTop: '4px' }}>
                  {lineage.audit.chain_intact ? (
                    <span className="badge badge-accept"><CheckCircle2 size={12} /> Intact</span>
                  ) : (
                    <span className="badge badge-quarantine"><XCircle size={12} /> Broken</span>
                  )}
                </div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Assurance Verdict</span>
                <div style={{ marginTop: '4px' }}>
                  {lineage.assurance.disposition ? (
                    <DispositionBadge disposition={lineage.assurance.disposition} />
                  ) : (
                    renderStageBadge(lineage.assurance.status)
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Detailed Pipeline Flow Nodes */}
          <div>
            <h3 style={{ fontSize: '1.1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>End-to-End Pipeline Lineage</span>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 'normal' }}>
                (Dataset → Model → Inference → Distribution → Evidence → Audit → Assurance)
              </span>
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* NODE 1: DATASET */}
              <div className="card" id="lineage-node-dataset">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '4px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Database size={16} />
                    </div>
                    <strong>1. DATASET</strong>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {renderStageBadge(lineage.dataset.status)}
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                      onClick={() => onNavigate('dataset')}
                    >
                      <ExternalLink size={12} /> Open
                    </button>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', fontSize: '0.85rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Dataset Identity</span>
                    <span className="font-mono">{lineage.dataset.dataset_identity || '—'}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Format</span>
                    <span>{lineage.dataset.format ? lineage.dataset.format.toUpperCase() : '—'}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Perceptual / SHA-256 Hash</span>
                    <span className="font-mono" style={{ fontSize: '0.8rem' }}>
                      {lineage.dataset.dataset_hash ? `${lineage.dataset.dataset_hash.slice(0, 24)}...` : '—'}
                    </span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Forensic Evidence</span>
                    <span>{lineage.dataset.evidence_count} artifact(s) indexed</span>
                  </div>
                </div>

                {/* Findings if any */}
                {lineage.dataset.findings.length > 0 && (
                  <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>
                      Relevant DT Findings ({lineage.dataset.findings.length}):
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {lineage.dataset.findings.map((f) => (
                        <div key={f.finding_id} style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', backgroundColor: 'var(--bg-tertiary)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.8rem' }}>
                          <SeverityBadge severity={f.severity} />
                          <code className="font-mono">{f.threat_id}</code>
                          <span>{f.title}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Arrow Down Connector */}
              <div style={{ display: 'flex', justifyContent: 'center', margin: '-8px 0', color: 'var(--text-muted)' }}>
                <ArrowDown size={18} />
              </div>

              {/* NODE 2: MODEL */}
              <div className="card" id="lineage-node-model">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '4px', backgroundColor: 'rgba(168, 85, 247, 0.1)', color: '#a855f7', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Cpu size={16} />
                    </div>
                    <strong>2. MODEL INTEGRITY</strong>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {renderStageBadge(lineage.model.status)}
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                      onClick={() => onNavigate('model')}
                    >
                      <ExternalLink size={12} /> Open
                    </button>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', fontSize: '0.85rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Candidate Model ID / Path</span>
                    <span className="font-mono">{lineage.model.candidate_model_id || '—'}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Model Weight Digest (SHA-256)</span>
                    <span className="font-mono" style={{ fontSize: '0.8rem' }}>
                      {lineage.model.model_digest ? `${lineage.model.model_digest.slice(0, 24)}...` : '—'}
                    </span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Reference / Golden Model</span>
                    <span>{lineage.model.reference_model || 'None (Standalone / Paired)'}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Supported Checks Run</span>
                    <span>
                      {lineage.model.supported_checks.length > 0
                        ? lineage.model.supported_checks.join(', ')
                        : 'None'}
                    </span>
                  </div>
                </div>

                {/* Unsupported Checks alert / disclosure */}
                {lineage.model.unsupported_checks.length > 0 && (
                  <div style={{ marginTop: '12px', padding: '10px 12px', borderRadius: '6px', backgroundColor: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.25)', fontSize: '0.85rem' }}>
                    <div style={{ fontWeight: 600, color: '#f59e0b', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                      <AlertTriangle size={14} /> Unsupported / Skipped Capabilities
                    </div>
                    {lineage.model.unsupported_checks.map((u) => (
                      <div key={u.check_id} style={{ fontSize: '0.8rem', color: 'var(--text-primary)', marginTop: '2px' }}>
                        <code className="font-mono" style={{ fontWeight: 600 }}>{u.check_id} — UNSUPPORTED</code>: {u.reason}
                      </div>
                    ))}
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Note: Unsupported checks are never converted to PASS and require explicit analyst review.
                    </div>
                  </div>
                )}

                {/* MT Findings if any */}
                {lineage.model.findings.length > 0 && (
                  <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>
                      Relevant MT Findings ({lineage.model.findings.length}):
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {lineage.model.findings.map((f) => (
                        <div key={f.finding_id} style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', backgroundColor: 'var(--bg-tertiary)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.8rem' }}>
                          <SeverityBadge severity={f.severity} />
                          <code className="font-mono">{f.threat_id}</code>
                          <span>{f.title}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Arrow Down Connector */}
              <div style={{ display: 'flex', justifyContent: 'center', margin: '-8px 0', color: 'var(--text-muted)' }}>
                <ArrowDown size={18} />
              </div>

              {/* NODE 3: INFERENCE */}
              <div className="card" id="lineage-node-inference">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '4px', backgroundColor: 'rgba(16, 185, 129, 0.1)', color: '#10b981', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <FileKey size={16} />
                    </div>
                    <strong>3. INFERENCE PROVENANCE</strong>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {renderStageBadge(lineage.inference.status)}
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                      onClick={() => onNavigate('provenance')}
                    >
                      <ExternalLink size={12} /> Open
                    </button>
                  </div>
                </div>

                {/* MODEL MISMATCH WARNING */}
                {lineage.inference.model_mismatch && (
                  <div className="alert alert-danger" style={{ marginBottom: '12px' }}>
                    <ShieldAlert size={18} style={{ flexShrink: 0 }} />
                    <div>
                      <strong>MODEL MISMATCH DETECTED:</strong> The model weight digest bound to this inference record does not match the candidate model currently registered in this session!
                      <div style={{ fontSize: '0.8rem', marginTop: '4px', wordBreak: 'break-all' }}>
                        Inference Digest: <code className="font-mono">{lineage.inference.bound_model_digest}</code>
                        <br />
                        Candidate Model Digest: <code className="font-mono">{lineage.model.model_digest || 'Unset'}</code>
                      </div>
                    </div>
                  </div>
                )}

                {/* TAMPER WARNING */}
                {lineage.inference.is_tampered && (
                  <div className="alert alert-danger" style={{ marginBottom: '12px' }}>
                    <ShieldAlert size={18} style={{ flexShrink: 0 }} />
                    <div>
                      <strong>CRYPTOGRAPHIC TAMPER DETECTED (IT-1):</strong> The digital signature or payload binding on this inference record failed Ed25519 verification.
                    </div>
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', fontSize: '0.85rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Inference Record UUID</span>
                    <span className="font-mono" style={{ fontSize: '0.8rem' }}>{lineage.inference.record_id || '—'}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Bound Model Weight Digest</span>
                    <span className="font-mono" style={{ fontSize: '0.8rem' }}>
                      {lineage.inference.bound_model_digest ? `${lineage.inference.bound_model_digest.slice(0, 24)}...` : '—'}
                    </span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Producer Identity / Sensor</span>
                    <span>{lineage.inference.producer_id || '—'}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Verification State</span>
                    <span style={{ fontWeight: 600 }}>{lineage.inference.verification_state}</span>
                  </div>
                </div>

                {/* IT Findings if any */}
                {lineage.inference.findings.length > 0 && (
                  <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>
                      Relevant IT Findings ({lineage.inference.findings.length}):
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {lineage.inference.findings.map((f) => (
                        <div key={f.finding_id} style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', backgroundColor: 'var(--bg-tertiary)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.8rem' }}>
                          <SeverityBadge severity={f.severity} />
                          <code className="font-mono">{f.threat_id}</code>
                          <span>{f.title}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Arrow Down Connector */}
              <div style={{ display: 'flex', justifyContent: 'center', margin: '-8px 0', color: 'var(--text-muted)' }}>
                <ArrowDown size={18} />
              </div>

              {/* NODE 4: DISTRIBUTION */}
              <div className="card" id="lineage-node-distribution">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '4px', backgroundColor: 'rgba(234, 179, 8, 0.1)', color: '#eab308', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Activity size={16} />
                    </div>
                    <strong>4. DISTRIBUTION SHIFT</strong>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {renderStageBadge(lineage.distribution.status)}
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                      onClick={() => onNavigate('shift')}
                    >
                      <ExternalLink size={12} /> Open
                    </button>
                  </div>
                </div>

                {!lineage.distribution.executed ? (
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: 0 }}>
                    Distribution shift analysis has not been executed for this session (distinguished from low/normal drift).
                  </p>
                ) : (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '0.85rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Overall Distance (W2 / MMD)</span>
                      <span style={{ fontWeight: 600 }}>{lineage.distribution.overall_distance?.toFixed(4) || '0.0000'}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Natural Drift Likelihood</span>
                      <span>{lineage.distribution.natural_drift_likelihood !== null ? `${Math.round((lineage.distribution.natural_drift_likelihood || 0) * 100)}%` : '—'}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Suspicious Manipulation</span>
                      <span style={{ color: (lineage.distribution.suspicious_manipulation_likelihood || 0) > 0.3 ? '#ef4444' : 'inherit' }}>
                        {lineage.distribution.suspicious_manipulation_likelihood !== null ? `${Math.round((lineage.distribution.suspicious_manipulation_likelihood || 0) * 100)}%` : '—'}
                      </span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Characterization</span>
                      <span>{lineage.distribution.characterization || 'Operational evaluation nominal'}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Arrow Down Connector */}
              <div style={{ display: 'flex', justifyContent: 'center', margin: '-8px 0', color: 'var(--text-muted)' }}>
                <ArrowDown size={18} />
              </div>

              {/* NODE 5: EVIDENCE */}
              <div className="card" id="lineage-node-evidence">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '4px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <FileCheck2 size={16} />
                    </div>
                    <strong>5. FORENSIC EVIDENCE BUNDLE</strong>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {renderStageBadge(lineage.evidence.status)}
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                      onClick={() => onNavigate('evidence')}
                    >
                      <ExternalLink size={12} /> View Evidence
                    </button>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', fontSize: '0.85rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Total Session Evidence</span>
                    <span style={{ fontWeight: 600, fontSize: '1rem' }}>{lineage.evidence.total_records} records</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Cryptographic Artifacts</span>
                    <span>{lineage.evidence.cryptographic_records}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Statistical Baselines</span>
                    <span>{lineage.evidence.statistical_records}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>File Artifacts</span>
                    <span>{lineage.evidence.artifact_records}</span>
                  </div>
                </div>

                {/* Evidence link CTA */}
                <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Underlying artifacts indexed in SQLite store. Verified via SHA-256 content hashes.
                  </span>
                  <button
                    className="btn btn-secondary"
                    style={{ fontSize: '0.75rem', padding: '4px 10px' }}
                    onClick={() => onNavigate('evidence')}
                  >
                    Open in Evidence Explorer
                  </button>
                </div>
              </div>

              {/* Arrow Down Connector */}
              <div style={{ display: 'flex', justifyContent: 'center', margin: '-8px 0', color: 'var(--text-muted)' }}>
                <ArrowDown size={18} />
              </div>

              {/* NODE 6: AUDIT */}
              <div className="card" id="lineage-node-audit">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '4px', backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Lock size={16} />
                    </div>
                    <strong>6. TAMPER-EVIDENT AUDIT LEDGER</strong>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {renderStageBadge(lineage.audit.status)}
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                      onClick={() => onNavigate('audit')}
                    >
                      <ExternalLink size={12} /> Open
                    </button>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '0.85rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Hash Chain Linkage</span>
                    <span style={{ fontWeight: 600, color: lineage.audit.chain_intact ? '#10b981' : '#ef4444' }}>
                      {lineage.audit.chain_intact ? 'MONOTONIC HASH CHAIN INTACT' : 'CHAIN COMPROMISED / BROKEN'}
                    </span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Active Audit Epoch</span>
                    <span>Epoch {lineage.audit.active_epoch}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Verified Audit Events</span>
                    <span>{lineage.audit.verified_events} / {lineage.audit.total_events} verified blocks</span>
                  </div>
                </div>
              </div>

              {/* Arrow Down Connector */}
              <div style={{ display: 'flex', justifyContent: 'center', margin: '-8px 0', color: 'var(--text-muted)' }}>
                <ArrowDown size={18} />
              </div>

              {/* NODE 7: ASSURANCE */}
              <div className="card" id="lineage-node-assurance">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '4px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <ShieldCheck size={16} />
                    </div>
                    <strong>7. HOLISTIC ASSURANCE ASSESSMENT</strong>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {lineage.assurance.disposition ? (
                      <DispositionBadge disposition={lineage.assurance.disposition} />
                    ) : (
                      renderStageBadge(lineage.assurance.status)
                    )}
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                      onClick={() => onNavigate('assurance')}
                    >
                      <ExternalLink size={12} /> Open
                    </button>
                  </div>
                </div>

                {!lineage.assurance.assessed ? (
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: 0 }}>
                    Assurance verdict has not yet been synthesized for this session. Visit Assurance Assessment to run weakest-link vetoes and calibrated Noisy-OR composite risk aggregation.
                  </p>
                ) : (
                  <div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '0.85rem', marginBottom: '12px' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Analyst Recommendation</span>
                        <div style={{ marginTop: '2px' }}>
                          {lineage.assurance.disposition && <DispositionBadge disposition={lineage.assurance.disposition} />}
                        </div>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Composite Risk Score (Noisy-OR)</span>
                        <span style={{ fontWeight: 600, fontSize: '1rem' }}>
                          {lineage.assurance.composite_risk_score !== null ? `${Math.round((lineage.assurance.composite_risk_score || 0) * 100)}%` : '—'}
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Pipeline Coverage State</span>
                        <span style={{ fontWeight: 600 }}>{lineage.assurance.coverage_state}</span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Contributing Finding IDs</span>
                        <span>{lineage.assurance.contributing_finding_ids.length} finding(s)</span>
                      </div>
                    </div>

                    {lineage.assurance.summary && (
                      <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-muted)', fontStyle: 'italic', borderTop: '1px solid var(--border-subtle)', paddingTop: '8px' }}>
                        "{lineage.assurance.summary}"
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Pipeline Dependencies Table */}
          <div className="card">
            <h3 style={{ fontSize: '1rem', marginBottom: '12px' }}>Pipeline Cryptographic Linkage Dependencies</h3>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Source Stage</th>
                    <th>Target Stage</th>
                    <th>Relationship</th>
                    <th>Link Status</th>
                    <th>Integrity Description</th>
                  </tr>
                </thead>
                <tbody>
                  {lineage.dependencies.map((d, idx) => (
                    <tr key={idx}>
                      <td style={{ fontWeight: 600 }}>{d.source}</td>
                      <td style={{ fontWeight: 600 }}>{d.target}</td>
                      <td>
                        <code className="font-mono" style={{ fontSize: '0.75rem' }}>{d.relationship}</code>
                      </td>
                      <td>
                        {d.is_valid ? (
                          <span className="badge badge-accept"><CheckCircle2 size={12} /> VALID</span>
                        ) : (
                          <span className="badge badge-quarantine"><XCircle size={12} /> BROKEN</span>
                        )}
                      </td>
                      <td style={{ fontSize: '0.85rem' }}>{d.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LineagePage;
