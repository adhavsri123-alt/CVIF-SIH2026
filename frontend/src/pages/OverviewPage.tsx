import React, { useEffect, useState } from 'react';
import {
  HealthStatusResponse,
  VersionResponse,
  AssuranceVerdict,
  ApiError,
} from '../types/api';
import api from '../api/client';
import { VerdictHero } from '../components/common/VerdictHero';
import { Database, Cpu, FileKey, Activity, ShieldCheck, AlertOctagon } from 'lucide-react';

interface OverviewPageProps {
  activeSessionId: string;
  onNavigate: (tab: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ activeSessionId, onNavigate }) => {
  const [health, setHealth] = useState<HealthStatusResponse | null>(null);
  const [version, setVersion] = useState<VersionResponse | null>(null);
  const [verdict, setVerdict] = useState<AssuranceVerdict | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadOverviewData();
  }, [activeSessionId]);

  const loadOverviewData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, v] = await Promise.all([api.getHealth(), api.getVersion()]);
      setHealth(h);
      setVersion(v);

      if (activeSessionId) {
        try {
          const vrd = await api.assessSession({ session_id: activeSessionId });
          setVerdict(vrd);
        } catch {
          // Assessment may not yet exist for this session
          setVerdict(null);
        }
      } else {
        setVerdict(null);
      }
    } catch (err: any) {
      const apiErr = err as ApiError;
      setError(apiErr.detail || 'Failed to connect to CVIF API.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      {error && (
        <div className="alert alert-danger">
          <AlertOctagon size={18} />
          <div>
            <strong>System Error</strong>: {error}
          </div>
        </div>
      )}

      {/* Hero Assurance Verdict */}
      <VerdictHero verdict={verdict} loading={loading} />

      {/* Four Pillars Quick Summary Cards */}
      <div className="grid-4" style={{ marginBottom: '24px' }}>
        {/* Pillar 1: Dataset */}
        <div className="card" style={{ cursor: 'pointer' }} onClick={() => onNavigate('dataset')}>
          <div className="card-header">
            <div className="card-title">
              <Database size={16} style={{ color: '#3b82f6' }} />
              Dataset Integrity
            </div>
          </div>
          <p style={{ fontSize: '0.85rem' }}>
            Protects against missing annotations, class imbalance, and poisoning (DT-1..6).
          </p>
          <span className="btn btn-secondary" style={{ width: '100%', fontSize: '0.8rem' }}>
            Inspect Datasets &rarr;
          </span>
        </div>

        {/* Pillar 2: Model */}
        <div className="card" style={{ cursor: 'pointer' }} onClick={() => onNavigate('model')}>
          <div className="card-header">
            <div className="card-title">
              <Cpu size={16} style={{ color: '#8b5cf6' }} />
              Model Integrity
            </div>
          </div>
          <p style={{ fontSize: '0.85rem' }}>
            Pre-flight AST scanning, backdoor Trojan detection, and weight tampering (MT-1..4).
          </p>
          <span className="btn btn-secondary" style={{ width: '100%', fontSize: '0.8rem' }}>
            Run Model Scan &rarr;
          </span>
        </div>

        {/* Pillar 3: Provenance */}
        <div className="card" style={{ cursor: 'pointer' }} onClick={() => onNavigate('provenance')}>
          <div className="card-header">
            <div className="card-title">
              <FileKey size={16} style={{ color: '#06b6d4' }} />
              Provenance
            </div>
          </div>
          <p style={{ fontSize: '0.85rem' }}>
            Ed25519 digital signatures, canonical hashing, and replay attack defense (IT-1..5).
          </p>
          <span className="btn btn-secondary" style={{ width: '100%', fontSize: '0.8rem' }}>
            Verify Provenance &rarr;
          </span>
        </div>

        {/* Pillar 4: Shift */}
        <div className="card" style={{ cursor: 'pointer' }} onClick={() => onNavigate('shift')}>
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} style={{ color: '#ec4899' }} />
              Distribution Shift
            </div>
          </div>
          <p style={{ fontSize: '0.85rem' }}>
            Distinguishes benign operational drift from adversarial distribution manipulation (DS-1..4).
          </p>
          <span className="btn btn-secondary" style={{ width: '100%', fontSize: '0.8rem' }}>
            Analyze Shift &rarr;
          </span>
        </div>
      </div>

      {/* System Status Row */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <ShieldCheck size={18} style={{ color: '#10b981' }} />
            Subsystem Verification Status
          </div>
        </div>

        <div className="grid-4" style={{ margin: 0 }}>
          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Audit Chain Ledger</span>
            <div style={{ marginTop: '4px', fontWeight: 600 }}>
              {health?.audit_chain.intact ? (
                <span style={{ color: '#10b981' }}>
                  &#x2714; Intact (Epoch {health.audit_chain.active_epoch || 1}: {health.audit_chain.verified_events} evt
                  {health.audit_chain.archive?.verified ? ' | Epoch 0 Sealed' : ''})
                </span>
              ) : (
                <span style={{ color: '#ef4444' }}>&#x2718; Tampered / Broken</span>
              )}
            </div>
          </div>

          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Metadata Catalogue</span>
            <div style={{ marginTop: '4px', fontWeight: 600 }}>
              {health?.database.accessible ? (
                <span style={{ color: '#10b981' }}>&#x2714; SQLite Online</span>
              ) : (
                <span style={{ color: '#ef4444' }}>&#x2718; Unavailable</span>
              )}
            </div>
          </div>

          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Evidence Store</span>
            <div style={{ marginTop: '4px', fontWeight: 600 }}>
              {health?.evidence_store.accessible ? (
                <span style={{ color: '#10b981' }}>&#x2714; Write-Once Directory Online</span>
              ) : (
                <span style={{ color: '#ef4444' }}>&#x2718; Directory Missing</span>
              )}
            </div>
          </div>

          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Air-Gap Enforcement</span>
            <div style={{ marginTop: '4px', fontWeight: 600 }}>
              {version?.air_gap_enforced ? (
                <span style={{ color: '#3b82f6' }}>&#x2714; Isolated (No External Sockets)</span>
              ) : (
                <span style={{ color: '#f59e0b' }}>Standard Mode</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
