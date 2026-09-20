import React, { useState } from 'react';
import {
  DistributionShiftResponse,
  ApiError,
  Finding,
} from '../types/api';
import api from '../api/client';
import { AttributionBar, ShiftMatrix } from '../components/common/ShiftComponents';
import { SeverityBadge, DispositionBadge } from '../components/common/Badges';
import { Activity, ShieldAlert, AlertOctagon, CheckCircle2 } from 'lucide-react';

interface ShiftPageProps {
  activeSessionId: string;
  onSessionCreated?: (sessionId: string) => void;
}

export const ShiftPage: React.FC<ShiftPageProps> = ({ activeSessionId, onSessionCreated }) => {
  const [refData, setRefData] = useState('');
  const [evalData, setEvalData] = useState('');
  const [loading, setLoading] = useState(false);
  const [shiftResult, setShiftResult] = useState<DistributionShiftResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!refData.trim() || !evalData.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await api.analyzeShift({
        reference_data: refData.trim(),
        evaluation_data: evalData.trim(),
        session_id: activeSessionId || undefined,
      });
      setShiftResult(res);
      if (onSessionCreated && res.session_id) {
        onSessionCreated(res.session_id);
      }
    } catch (err: any) {
      setError(err as ApiError);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      <div style={{ marginBottom: '24px' }}>
        <h1>Distribution Shift & Manipulation Analysis</h1>
        <p>
          Compare reference baseline datasets against operational deployments across four statistical dimensions:
          Covariate (DS-1), Semantic (DS-2), Environmental (DS-3), and Adversarial Manipulation (DS-4).
        </p>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertOctagon size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Shift Analysis Failed [{error.error_type}]</strong>: {error.detail}
            {error.request_id && (
              <div style={{ fontSize: '0.8rem', marginTop: '4px' }}>
                Request-ID: <code className="font-mono">{error.request_id}</code>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Inputs Form */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Activity size={18} style={{ color: '#ec4899' }} />
            Execute Distribution Shift Evaluation
          </div>
        </div>

        <form onSubmit={handleAnalyze}>
          <div className="grid-2">
            <div className="form-group">
              <label className="form-label">Golden Reference Baseline Dataset Path</label>
              <input
                type="text"
                className="form-input font-mono"
                value={refData}
                onChange={(e) => setRefData(e.target.value)}
                placeholder="e.g. data/reference_baseline or path/to/ref"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Operational Evaluation Dataset Path</label>
              <input
                type="text"
                className="form-input font-mono"
                value={evalData}
                onChange={(e) => setEvalData(e.target.value)}
                placeholder="e.g. data/operational_stream or path/to/eval"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading || !refData.trim() || !evalData.trim()}
          >
            {loading ? 'Computing High-Dimensional Shift Statistics...' : 'Analyze Distribution Shift (DS-1..4)'}
          </button>
        </form>
      </div>

      {/* Results View */}
      {shiftResult && (
        <div>
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                {shiftResult.overall_shift_detected ? (
                  <ShieldAlert size={20} style={{ color: '#ef4444' }} />
                ) : (
                  <CheckCircle2 size={20} style={{ color: '#10b981' }} />
                )}
                Shift Assessment Result: {shiftResult.overall_shift_detected ? 'STATISTICAL SHIFT DETECTED' : 'NOMINAL STABILITY'}
              </div>
              <span className={`badge ${shiftResult.overall_shift_detected ? 'badge-quarantine' : 'badge-accept'}`}>
                {shiftResult.overall_shift_detected ? 'DISTRIBUTION SHIFTED' : 'IN DISTRIBUTION'}
              </span>
            </div>

            <AttributionBar
              naturalDrift={shiftResult.natural_drift_likelihood ?? (shiftResult.overall_shift_detected ? 0.35 : 0.95)}
              suspiciousManipulation={shiftResult.suspicious_manipulation_likelihood ?? (shiftResult.overall_shift_detected ? 0.65 : 0.05)}
            />

            {shiftResult.characterization && (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: '-8px 0 12px 0' }}>
                Forensic Classification: <strong style={{ color: 'var(--text-primary)' }}>{shiftResult.characterization.replace(/_/g, ' ')}</strong>
                {typeof shiftResult.overall_distance === 'number' && (
                  <span> &bull; Divergence Metric: <code className="font-mono">{shiftResult.overall_distance.toFixed(4)}</code></span>
                )}
              </div>
            )}

            <h4 style={{ margin: '16px 0 8px 0' }}>Dimension Breakdown (DS-1 through DS-4)</h4>
            <ShiftMatrix dimensions={shiftResult.dimensions} />
          </div>

          {shiftResult.findings.length > 0 && (
            <div className="card">
              <div className="card-header">
                <div className="card-title">
                  <ShieldAlert size={18} style={{ color: '#f59e0b' }} />
                  Shift Findings ({shiftResult.findings_count})
                </div>
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Dimension</th>
                      <th>Severity</th>
                      <th>Description</th>
                      <th>Confidence</th>
                      <th>Recommendation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shiftResult.findings.map((f: Finding) => (
                      <tr key={f.finding_id}>
                        <td className="font-mono" style={{ fontWeight: 600 }}>{f.threat_id}</td>
                        <td><SeverityBadge severity={f.severity} /></td>
                        <td>
                          <div style={{ fontWeight: 600 }}>{f.title}</div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{f.description}</div>
                        </td>
                        <td className="font-mono">{(f.confidence * 100).toFixed(0)}%</td>
                        <td><DispositionBadge disposition={f.recommended_disposition} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
