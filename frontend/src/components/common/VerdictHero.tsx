import React from 'react';
import { AssuranceVerdict } from '../../types/api';
import { DispositionBadge } from './Badges';
import { RiskGauge } from './RiskGauge';
import { AlertOctagon } from 'lucide-react';

interface VerdictHeroProps {
  verdict: AssuranceVerdict | null;
  loading?: boolean;
}

export const VerdictHero: React.FC<VerdictHeroProps> = ({ verdict, loading }) => {
  if (loading) {
    return (
      <div className="card" style={{ padding: '32px', textAlign: 'center' }}>
        <p style={{ color: '#9ca3af' }}>Evaluating holistic assurance verdict...</p>
      </div>
    );
  }

  if (!verdict) {
    return (
      <div
        className="card"
        style={{
          padding: '24px',
          borderStyle: 'dashed',
          borderColor: 'var(--border-subtle)',
          textAlign: 'center',
        }}
      >
        <p style={{ margin: 0, color: 'var(--text-muted)' }}>
          No session assurance assessment evaluated yet. Select or trigger an assessment.
        </p>
      </div>
    );
  }

  const isQuarantine = verdict.disposition === 'QUARANTINE';
  const isReview = verdict.disposition === 'REVIEW';

  return (
    <div
      className="card"
      style={{
        borderLeft: `4px solid ${
          isQuarantine ? '#ef4444' : isReview ? '#f59e0b' : '#10b981'
        }`,
        backgroundColor: 'var(--bg-secondary)',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '20px',
        }}
      >
        <div style={{ flex: 1, minWidth: '280px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
            <h2 style={{ margin: 0, fontSize: '1.4rem' }}>Assurance Verdict</h2>
            <DispositionBadge disposition={verdict.disposition} />
          </div>

          <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', margin: '8px 0' }}>
            {verdict.summary}
          </p>

          <div style={{ display: 'flex', gap: '16px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            <span>Session: <code className="font-mono">{verdict.session_id.substring(0, 8)}...</code></span>
            <span>Evaluated: {new Date(verdict.timestamp).toLocaleTimeString()}</span>
            <span>Contributing Findings: {verdict.contributing_finding_ids.length}</span>
          </div>

          {isQuarantine && (
            <div
              className="alert alert-danger"
              style={{ marginTop: '12px', marginBottom: 0, padding: '10px 14px' }}
            >
              <AlertOctagon size={18} style={{ flexShrink: 0 }} />
              <div>
                <strong>CRITICAL INTEGRITY VETO</strong>: Automated pipeline deployment blocked.
                Asset quarantined pending manual forensic investigation.
              </div>
            </div>
          )}

          {verdict.unsupported_checks && verdict.unsupported_checks.length > 0 && (
            <div style={{ marginTop: '10px', fontSize: '0.8rem' }}>
              <span style={{ color: '#eab308' }}>Unsupported Checks: </span>
              {verdict.unsupported_checks.map((chk, i) => (
                <span
                  key={i}
                  style={{
                    backgroundColor: 'rgba(234, 179, 8, 0.1)',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    marginRight: '6px',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  {chk}
                </span>
              ))}
            </div>
          )}
        </div>

        <div style={{ padding: '0 16px' }}>
          <RiskGauge score={verdict.composite_risk_score} size={150} label="Composite Risk Score" />
        </div>
      </div>
    </div>
  );
};
