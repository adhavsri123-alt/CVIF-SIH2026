import React, { useState, useEffect } from 'react';
import {
  AssuranceVerdict,
  ApiError,
} from '../types/api';
import api from '../api/client';
import { VerdictHero } from '../components/common/VerdictHero';
import { ShieldCheck, AlertOctagon } from 'lucide-react';

interface AssurancePageProps {
  activeSessionId: string;
}

export const AssurancePage: React.FC<AssurancePageProps> = ({ activeSessionId }) => {
  const [sessionIdInput, setSessionIdInput] = useState(activeSessionId);
  const [verdict, setVerdict] = useState<AssuranceVerdict | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    setSessionIdInput(activeSessionId);
    if (activeSessionId) {
      loadAssessment(activeSessionId);
    }
  }, [activeSessionId]);

  const loadAssessment = async (sessId: string) => {
    if (!sessId.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const res = await api.assessSession({ session_id: sessId.trim() });
      setVerdict(res);
    } catch (err: any) {
      setError(err as ApiError);
      setVerdict(null);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadAssessment(sessionIdInput);
  };

  return (
    <div className="page-container">
      <div style={{ marginBottom: '24px' }}>
        <h1>Holistic Assurance Aggregation & Verdict</h1>
        <p>
          Aggregates multi-dimensional evidence across Data, Models, Provenance, and Distribution Shift using
          Weakest-Link Critical Vetoes and calibrated Noisy-OR composite risk modeling.
        </p>
      </div>

      {/* Session Form */}
      <div className="card" style={{ marginBottom: '24px' }}>
        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '12px', alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label className="form-label">Analysis Session UUID</label>
            <input
              type="text"
              className="form-input font-mono"
              value={sessionIdInput}
              onChange={(e) => setSessionIdInput(e.target.value)}
              placeholder="e.g. 12345678-1234-5678-1234-567812345678"
              required
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={loading || !sessionIdInput.trim()}>
            {loading ? 'Synthesizing Verdict...' : 'Synthesize Assurance Verdict'}
          </button>
        </form>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertOctagon size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Assessment Synthesis Failed [{error.error_type}]</strong>: {error.detail}
            {error.request_id && (
              <div style={{ fontSize: '0.8rem', marginTop: '4px' }}>
                Request-ID: <code className="font-mono">{error.request_id}</code>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Hero Verdict Display */}
      <VerdictHero verdict={verdict} loading={loading} />

      {/* Mathematical Breakdown Notes */}
      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-header">
          <div className="card-title">
            <ShieldCheck size={18} style={{ color: '#3b82f6' }} />
            Authoritative Aggregation Rules (Phases 7 &amp; 10)
          </div>
        </div>
        <div className="grid-2">
          <div>
            <h4 style={{ color: '#ef4444', marginBottom: '6px' }}>1. Weakest-Link Critical Veto</h4>
            <p style={{ fontSize: '0.85rem' }}>
              If any single integrity check across Data, Models, or Provenance detects a CRITICAL severity violation
              (e.g. Model Trojan Backdoor MT-3 or Provenance Forgery IT-1), the pipeline immediately forces disposition
              to <strong style={{ color: '#ef4444' }}>QUARANTINE</strong> regardless of other passing checks.
            </p>
          </div>
          <div>
            <h4 style={{ color: '#3b82f6', marginBottom: '6px' }}>2. Calibrated Noisy-OR Risk Score</h4>
            <p style={{ fontSize: '0.85rem' }}>
              Independent non-critical findings combine probabilistically: 
              <code className="font-mono" style={{ display: 'block', margin: '4px 0', color: '#60a5fa' }}>
                R = 1 - &prod; (1 - w_i &times; c_i)
              </code>
              ensuring monotonic risk scaling while suppressing subjective threshold drift.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
