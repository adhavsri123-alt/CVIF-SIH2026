import React, { useState } from 'react';
import {
  DatasetIngestResponse,
  DatasetScanResponse,
  ApiError,
  Finding,
} from '../types/api';
import api from '../api/client';
import { SeverityBadge, DispositionBadge } from '../components/common/Badges';
import { Database, Upload, ShieldAlert, CheckCircle, AlertOctagon } from 'lucide-react';

interface DatasetPageProps {
  activeSessionId: string;
  onSessionCreated?: (sessionId: string) => void;
}

export const DatasetPage: React.FC<DatasetPageProps> = ({ activeSessionId, onSessionCreated }) => {
  // Ingest form state
  const [dataDir, setDataDir] = useState('');
  const [format, setFormat] = useState<'auto' | 'coco' | 'yolo'>('auto');
  const [contributorId, setContributorId] = useState('local_contributor');
  const [ingestLoading, setIngestLoading] = useState(false);
  const [ingestResult, setIngestResult] = useState<DatasetIngestResponse | null>(null);

  // Scan state
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState<DatasetScanResponse | null>(null);

  const [error, setError] = useState<ApiError | null>(null);

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!dataDir.trim()) return;

    setIngestLoading(true);
    setError(null);
    try {
      const res = await api.ingestDataset({
        data_dir: dataDir.trim(),
        format,
        contributor_id: contributorId.trim() || undefined,
      });
      setIngestResult(res);
    } catch (err: any) {
      setError(err as ApiError);
    } finally {
      setIngestLoading(false);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!dataDir.trim()) return;

    setScanLoading(true);
    setError(null);
    try {
      const res = await api.scanDataset({
        data_dir: dataDir.trim(),
        session_id: activeSessionId || undefined,
        contributor_id: contributorId.trim() || undefined,
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
        <h1>Dataset Integrity Assurance</h1>
        <p>
          Ingest raw computer vision datasets, validate annotation schema boundaries, and execute the
          authoritative DT-1 through DT-6 integrity threat battery.
        </p>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertOctagon size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Operation Failed [{error.error_type}]</strong>: {error.detail}
            {error.request_id && (
              <div style={{ fontSize: '0.8rem', marginTop: '4px' }}>
                Request-ID: <code className="font-mono">{error.request_id}</code>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Panel 1: Ingest Form */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Upload size={18} style={{ color: '#3b82f6' }} />
              Ingest & Register Dataset
            </div>
          </div>

          <form onSubmit={handleIngest}>
            <div className="form-group">
              <label className="form-label">Server Dataset Directory (Path on Server)</label>
              <input
                type="text"
                className="form-input font-mono"
                value={dataDir}
                onChange={(e) => setDataDir(e.target.value)}
                placeholder="e.g. data/sample_dataset or absolute path"
                required
              />
            </div>

            <div className="grid-2" style={{ gap: '12px' }}>
              <div className="form-group">
                <label className="form-label">Format Origin</label>
                <select
                  className="form-select"
                  value={format}
                  onChange={(e) => setFormat(e.target.value as any)}
                >
                  <option value="auto">Auto-Detect</option>
                  <option value="coco">COCO</option>
                  <option value="yolo">YOLO</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Contributor ID</label>
                <input
                  type="text"
                  className="form-input"
                  value={contributorId}
                  onChange={(e) => setContributorId(e.target.value)}
                  placeholder="e.g. unit_bravo_recon"
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '12px', marginTop: '12px' }}>
              <button type="submit" className="btn btn-primary" disabled={ingestLoading || !dataDir.trim()}>
                {ingestLoading ? 'Ingesting...' : 'Ingest & Catalog'}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleScan}
                disabled={scanLoading || !dataDir.trim()}
              >
                {scanLoading ? 'Scanning DT-1..6...' : 'Run DT Threat Scan'}
              </button>
            </div>
          </form>

          {ingestResult && (
            <div style={{ marginTop: '20px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
              <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#10b981' }}>
                <CheckCircle size={16} /> Ingestion Succeeded [{ingestResult.status}]
              </h4>
              <div style={{ fontSize: '0.85rem', marginTop: '8px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                <div>Asset ID: <code className="font-mono">{ingestResult.asset_id.substring(0, 8)}...</code></div>
                <div>Format: <strong>{ingestResult.format.toUpperCase()}</strong></div>
                <div>Images: <strong>{ingestResult.image_count}</strong></div>
                <div>Annotations: <strong>{ingestResult.annotation_count}</strong></div>
              </div>
            </div>
          )}
        </div>

        {/* Panel 2: Threat Scope Description */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Database size={18} style={{ color: '#06b6d4' }} />
              Monitored Dataset Threats (DT-1..6)
            </div>
          </div>
          <ul style={{ listStyle: 'none', padding: 0, fontSize: '0.85rem' }}>
            <li style={{ marginBottom: '10px' }}>
              <strong className="font-mono" style={{ color: '#3b82f6' }}>DT-1 Trigger Injection:</strong> High-contrast backdoor patches, triggers, or suspicious injected patterns.
            </li>
            <li style={{ marginBottom: '10px' }}>
              <strong className="font-mono" style={{ color: '#3b82f6' }}>DT-2 Label Flipping:</strong> Feature-neighborhood label contradictions / suspicious label inconsistencies.
            </li>
            <li style={{ marginBottom: '10px' }}>
              <strong className="font-mono" style={{ color: '#3b82f6' }}>DT-3 Systematic Mislabelling:</strong> Asymmetric or systematic directional class confusion.
            </li>
            <li style={{ marginBottom: '10px' }}>
              <strong className="font-mono" style={{ color: '#3b82f6' }}>DT-4 Near-Duplicate Flooding:</strong> Duplicate or near-duplicate samples that may distort evaluation.
            </li>
            <li style={{ marginBottom: '10px' }}>
              <strong className="font-mono" style={{ color: '#3b82f6' }}>DT-5 OOD Insertion:</strong> Statistical feature-dispersion outliers beyond the configured threshold.
            </li>
            <li style={{ marginBottom: '10px' }}>
              <strong className="font-mono" style={{ color: '#3b82f6' }}>DT-6 Contributor Risk:</strong> Contributor/source attribution and associated integrity risk.
            </li>
          </ul>
        </div>
      </div>

      {/* Scan Results Table */}
      {scanResult && (
        <div className="card" style={{ marginTop: '24px' }}>
          <div className="card-header">
            <div className="card-title">
              <ShieldAlert size={18} style={{ color: scanResult.has_critical_findings ? '#ef4444' : '#10b981' }} />
              Scan Findings ({scanResult.findings_count} findings)
            </div>
            {scanResult.has_critical_findings && (
              <span className="badge badge-quarantine">CRITICAL FINDINGS DETECTED</span>
            )}
          </div>

          {scanResult.findings.length === 0 ? (
            <p style={{ color: '#10b981' }}>No integrity violations detected. Dataset passed nominal checks.</p>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Threat ID</th>
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
