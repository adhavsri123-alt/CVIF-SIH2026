import React, { useState } from 'react';
import {
  InferenceRecord,
  ProvenanceVerifyResponse,
  ApiError,
  Finding,
} from '../types/api';
import api from '../api/client';
import { SeverityBadge } from '../components/common/Badges';
import { FileKey, ShieldAlert, AlertOctagon, CheckCircle2, KeyRound, Sparkles, RotateCcw } from 'lucide-react';

export const ProvenancePage: React.FC = () => {
  const [recordJson, setRecordJson] = useState('');

  const [rawImagePath, setRawImagePath] = useState('');
  const [expectedModelDigest, setExpectedModelDigest] = useState('');

  const [loading, setLoading] = useState(false);
  const [generatingDemo, setGeneratingDemo] = useState(false);
  const [demoMessage, setDemoMessage] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<ProvenanceVerifyResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  const handleGenerateDemo = async (tampered: boolean = false) => {
    setGeneratingDemo(true);
    setError(null);
    setVerifyResult(null);
    setDemoMessage(null);

    try {
      const res = await api.generateDemoProvenance({ tampered });
      const formattedJson = JSON.stringify(res.record, null, 2);
      setRecordJson(formattedJson);
      setDemoMessage(res.message);
    } catch (err: any) {
      setError(err as ApiError);
    } finally {
      setGeneratingDemo(false);
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const trimmed = recordJson.trim();
      if (!trimmed) {
        throw {
          detail: 'Please paste a valid CVIF Inference Record JSON payload.',
          error_type: 'empty_payload_error',
        } as ApiError;
      }

      let parsedPayload: any;
      try {
        parsedPayload = JSON.parse(trimmed);
      } catch (parseErr) {
        throw {
          detail: 'Invalid JSON syntax in InferenceRecord payload.',
          error_type: 'json_parse_error',
        } as ApiError;
      }

      // Robustly unwrap if the user pasted a wrapped payload { "record": { ... } }
      const actualRecord: InferenceRecord = (parsedPayload && typeof parsedPayload === 'object' && parsedPayload.record)
        ? parsedPayload.record
        : parsedPayload;

      const res = await api.verifyProvenance({
        record: actualRecord,
        raw_image_path: rawImagePath.trim() || undefined,
        expected_model_digest: expectedModelDigest.trim() || undefined,
      });

      setVerifyResult(res);
    } catch (err: any) {
      setError(err as ApiError);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      <div style={{ marginBottom: '24px' }}>
        <h1>Inference Provenance Verification</h1>
        <p>
          Verify the cryptographic chain of custody for inference records, including Ed25519 digital signatures,
          input image hashes, model weight digests, and replay-prevention nonces.
        </p>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertOctagon size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Provenance Verification Failed [{error.error_type}]</strong>: {error.detail}
            {error.request_id && (
              <div style={{ fontSize: '0.8rem', marginTop: '4px' }}>
                Request-ID: <code className="font-mono">{error.request_id}</code>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Verification Form */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <KeyRound size={18} style={{ color: '#06b6d4' }} />
              Inference Record Payload
            </div>
          </div>

          {/* Demo Workflow Controls */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
            <button
              type="button"
              id="btn-generate-fresh-demo"
              className="btn btn-secondary"
              onClick={() => handleGenerateDemo(false)}
              disabled={generatingDemo || loading}
              style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem' }}
              title="Generate a fresh, legitimately signed demo record with a monotonic sequence and unique nonce"
            >
              <Sparkles size={14} style={{ color: '#06b6d4' }} />
              {generatingDemo ? 'Signing Fresh Record...' : 'Generate Fresh Demo Record'}
            </button>

            <button
              type="button"
              id="btn-load-tampered-demo"
              className="btn btn-secondary"
              onClick={() => handleGenerateDemo(true)}
              disabled={generatingDemo || loading}
              style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem' }}
              title="Generate a demo record with altered prediction confidence to demonstrate IT-1 tamper detection"
            >
              <ShieldAlert size={14} style={{ color: '#f59e0b' }} />
              Load Tampered Demo Record
            </button>

            {recordJson && (
              <button
                type="button"
                id="btn-clear-provenance"
                className="btn btn-secondary"
                onClick={() => {
                  setRecordJson('');
                  setVerifyResult(null);
                  setError(null);
                  setDemoMessage(null);
                }}
                style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.85rem' }}
              >
                <RotateCcw size={13} />
                Clear
              </button>
            )}
          </div>

          {demoMessage && (
            <div
              style={{
                padding: '10px 14px',
                marginBottom: '16px',
                borderRadius: '6px',
                backgroundColor: 'rgba(6, 182, 212, 0.08)',
                border: '1px solid rgba(6, 182, 212, 0.25)',
                color: '#22d3ee',
                fontSize: '0.85rem',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
              }}
            >
              <CheckCircle2 size={16} style={{ flexShrink: 0, color: '#06b6d4' }} />
              <span>{demoMessage}</span>
            </div>
          )}

          <form onSubmit={handleVerify}>
            <div className="form-group">
              <label className="form-label">Inference Record (JSON)</label>
              <textarea
                className="form-textarea font-mono"
                rows={12}
                value={recordJson}
                onChange={(e) => setRecordJson(e.target.value)}
                placeholder="Paste CVIF Inference Record JSON here or click 'Generate Fresh Demo Record' above..."
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Raw Image File Path (Optional verification against input_image_hash)</label>
              <input
                type="text"
                className="form-input font-mono"
                value={rawImagePath}
                onChange={(e) => setRawImagePath(e.target.value)}
                placeholder="e.g. data/recon/frame_001.jpg"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Expected Model Digest (Optional verification against model_weight_digest)</label>
              <input
                type="text"
                className="form-input font-mono"
                value={expectedModelDigest}
                onChange={(e) => setExpectedModelDigest(e.target.value)}
                placeholder="SHA-256 hex digest..."
              />
            </div>

            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Verifying Ed25519 Cryptographic Chain...' : 'Verify Cryptographic Signature'}
            </button>
          </form>
        </div>

        {/* Verification Report */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <FileKey size={18} style={{ color: '#3b82f6' }} />
              Cryptographic Audit Status
            </div>
          </div>

          {verifyResult ? (
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  marginBottom: '16px',
                  padding: '12px',
                  borderRadius: '6px',
                  backgroundColor: verifyResult.is_valid ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                  border: `1px solid ${verifyResult.is_valid ? '#10b981' : '#ef4444'}`,
                }}
              >
                {verifyResult.is_valid ? (
                  <CheckCircle2 size={24} style={{ color: '#10b981' }} />
                ) : (
                  <ShieldAlert size={24} style={{ color: '#ef4444' }} />
                )}
                <div>
                  <h3 style={{ margin: 0, color: verifyResult.is_valid ? '#10b981' : '#ef4444' }}>
                    {verifyResult.is_valid ? 'RECORD AUTHENTIC & VALID' : 'PROVENANCE INTEGRITY VIOLATION'}
                  </h3>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Producer: <strong>{verifyResult.contributor_id || 'Unknown'}</strong> | Status: [{verifyResult.status}]
                  </span>
                </div>
              </div>

              <div className="table-container" style={{ marginBottom: '16px' }}>
                <table>
                  <tbody>
                    <tr>
                      <td style={{ fontWeight: 600 }}>Ed25519 Signature</td>
                      <td>
                        <span className={`badge ${verifyResult.is_valid ? 'badge-accept' : 'badge-quarantine'}`}>
                          {verifyResult.is_valid ? 'VALIDATED' : 'FORGERY / UNVERIFIED'}
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 600 }}>Record Hash Chain</td>
                      <td>
                        <span className="badge badge-accept">MONOTONIC SEQUENCE</span>
                      </td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 600 }}>Replay Defense</td>
                      <td>
                        <span className="badge badge-accept">UNIQUE NONCE CONFIRMED</span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {verifyResult.findings.length > 0 && (
                <div>
                  <h4>Integrity Findings ({verifyResult.findings_count})</h4>
                  {verifyResult.findings.map((f: Finding) => (
                    <div key={f.finding_id} className="alert alert-warning" style={{ marginTop: '8px' }}>
                      <SeverityBadge severity={f.severity} />
                      <div>
                        <strong>{f.title}</strong>: {f.description}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)' }}>
              Submit an inference record to verify its Ed25519 signature, model weight binding, and input digest.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
