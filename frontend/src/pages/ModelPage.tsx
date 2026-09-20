import React, { useState } from 'react';
import {
  ModelSafetyScanResponse,
  ModelScanResponse,
  ApiError,
  Finding,
} from '../types/api';
import api from '../api/client';
import { SeverityBadge, DispositionBadge } from '../components/common/Badges';
import { Cpu, ShieldAlert, AlertOctagon, CheckCircle2, Crosshair } from 'lucide-react';

interface ModelPageProps {
  activeSessionId: string;
  onSessionCreated?: (sessionId: string) => void;
}

export const ModelPage: React.FC<ModelPageProps> = ({ activeSessionId, onSessionCreated }) => {
  const [modelPath, setModelPath] = useState('');
  const [refWeights, setRefWeights] = useState('');

  // Pre-flight state
  const [safetyLoading, setSafetyLoading] = useState(false);
  const [safetyResult, setSafetyResult] = useState<ModelSafetyScanResponse | null>(null);

  // Battery scan state
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ModelScanResponse | null>(null);

  const [error, setError] = useState<ApiError | null>(null);

  const handleSafetyScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!modelPath.trim()) return;

    setSafetyLoading(true);
    setError(null);
    try {
      const res = await api.scanModelSafety({ model_path: modelPath.trim() });
      setSafetyResult(res);
    } catch (err: any) {
      setError(err as ApiError);
    } finally {
      setSafetyLoading(false);
    }
  };

  const handleBatteryScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!modelPath.trim()) return;

    setScanLoading(true);
    setError(null);
    try {
      const res = await api.scanModel({
        model_path: modelPath.trim(),
        reference_weights: refWeights.trim() || undefined,
        session_id: activeSessionId || undefined,
      });
      setScanResult(res);
      if (onSessionCreated && res.session_id) {
        onSessionCreated(res.session_id);
      }
    } catch (err: any) {
      setError(err as ApiError);
    } finally {
      setScanLoading(false);
    }
  };

  return (
    <div className="page-container">
      <div style={{ marginBottom: '24px' }}>
        <h1>Model Integrity & Trojan Assurance</h1>
        <p>
          Enforce pre-flight static deserialization safety, verify weight fingerprints against golden baselines,
          and execute Neural Cleanse backdoor Trojan detection (MT-1..4).
        </p>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertOctagon size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Model Scan Violation [{error.error_type}]</strong>: {error.detail}
            {error.request_id && (
              <div style={{ fontSize: '0.8rem', marginTop: '4px' }}>
                Request-ID: <code className="font-mono">{error.request_id}</code>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Form Panel */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={18} style={{ color: '#8b5cf6' }} />
              Model Verification Workflow
            </div>
          </div>

          <form>
            <div className="form-group">
              <label className="form-label">Candidate Model File Path (on Server)</label>
              <input
                type="text"
                className="form-input font-mono"
                value={modelPath}
                onChange={(e) => setModelPath(e.target.value)}
                placeholder="e.g. models/yolov8n.onnx or models/weights.pth"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Golden Reference Weights Path (Optional for MT-2)</label>
              <input
                type="text"
                className="form-input font-mono"
                value={refWeights}
                onChange={(e) => setRefWeights(e.target.value)}
                placeholder="e.g. models/golden_reference.pt"
              />
            </div>

            <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleSafetyScan}
                disabled={safetyLoading || !modelPath.trim()}
              >
                {safetyLoading ? 'Checking Safety...' : '1. Pre-Flight Safety Scan'}
              </button>

              <button
                type="button"
                className="btn btn-primary"
                onClick={handleBatteryScan}
                disabled={scanLoading || !modelPath.trim()}
              >
                {scanLoading ? 'Running Battery MT-1..4...' : '2. Run Full Model Battery'}
              </button>
            </div>
          </form>

          {/* Safety Result Badge */}
          {safetyResult && (
            <div
              style={{
                marginTop: '20px',
                borderTop: '1px solid var(--border-subtle)',
                paddingTop: '16px',
              }}
            >
              <h4
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  color: safetyResult.is_safe ? '#10b981' : '#ef4444',
                }}
              >
                {safetyResult.is_safe ? <CheckCircle2 size={16} /> : <AlertOctagon size={16} />}
                Pre-Flight Static Safety: {safetyResult.is_safe ? 'VERIFIED SAFE' : 'UNSAFE FILE BLOCKED'}
              </h4>
              <div style={{ fontSize: '0.85rem', marginTop: '8px' }}>
                <div>Detected Format: <strong className="font-mono">{safetyResult.detected_format}</strong></div>
                <div>SHA-256 Digest: <code className="font-mono">{safetyResult.file_hash.substring(0, 16)}...</code></div>
                {safetyResult.errors.length > 0 && (
                  <div style={{ color: '#ef4444', marginTop: '4px' }}>
                    Errors: {safetyResult.errors.join(', ')}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Battery Scope Description */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Crosshair size={18} style={{ color: '#ec4899' }} />
              Model Threat Battery (MT-1..4)
            </div>
          </div>
          <ul style={{ listStyle: 'none', padding: 0, fontSize: '0.85rem' }}>
            <li style={{ marginBottom: '12px' }}>
              <strong className="font-mono" style={{ color: '#8b5cf6' }}>MT-1 Architecture Safety:</strong> Validates computational graph against hazardous layer types and malicious operators.
            </li>
            <li style={{ marginBottom: '12px' }}>
              <strong className="font-mono" style={{ color: '#8b5cf6' }}>MT-2 Weight Tampering:</strong> Layer-by-layer fingerprinting against authorized cryptographic digests.
            </li>
            <li style={{ marginBottom: '12px' }}>
              <strong className="font-mono" style={{ color: '#8b5cf6' }}>MT-3 Trojan & Backdoor (Neural Cleanse):</strong> Computes L1 trigger norm optimization across classes to detect backdoors with anomaly index &gt; 2.0.
            </li>
            <li style={{ marginBottom: '12px' }}>
              <strong className="font-mono" style={{ color: '#8b5cf6' }}>MT-4 Evasion Vulnerability:</strong> Evaluates adversarial sensitivity against normalized input perturbations.
            </li>
          </ul>
        </div>
      </div>

      {/* Battery Scan Results */}
      {scanResult && (
        <div className="card" style={{ marginTop: '24px' }}>
          <div className="card-header">
            <div className="card-title">
              <ShieldAlert size={18} style={{ color: scanResult.has_critical_findings ? '#ef4444' : '#10b981' }} />
              Battery Results [{scanResult.status}] — {scanResult.total_findings} findings
            </div>
            {scanResult.has_critical_findings && (
              <span className="badge badge-quarantine">CRITICAL FINDINGS DETECTED</span>
            )}
          </div>

          <div style={{ marginBottom: '14px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Executed Analyses: {scanResult.executed_analyses.join(', ') || 'MT-1, MT-2, MT-3, MT-4'}
          </div>

          {scanResult.findings.length === 0 ? (
            <p style={{ color: '#10b981' }}>All model checks passed nominal thresholds. No backdoor triggers detected.</p>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Threat</th>
                    <th>Severity</th>
                    <th>Title & Description</th>
                    <th>Confidence</th>
                    <th>Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {scanResult.findings.map((f: Finding) => (
                    <tr key={f.finding_id}>
                      <td className="font-mono" style={{ fontWeight: 600 }}>{f.threat_id}</td>
                      <td><SeverityBadge severity={f.severity} /></td>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{f.title}</div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{f.description}</div>
                      </td>
                      <td className="font-mono">{(f.confidence * 100).toFixed(0)}%</td>
                      <td><DispositionBadge disposition={f.recommended_disposition} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
