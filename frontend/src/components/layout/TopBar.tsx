import React, { useState } from 'react';
import { Shield, ShieldAlert, Key, RefreshCw, Radio } from 'lucide-react';
import { HealthStatusResponse, VersionResponse } from '../../types/api';

interface TopBarProps {
  health: HealthStatusResponse | null;
  version: VersionResponse | null;
  activeSessionId: string;
  onSessionChange: (sessionId: string) => void;
  onRefresh: () => void;
  onOpenApiKeyModal: () => void;
  hasApiKey: boolean;
  refreshing?: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  health,
  version,
  activeSessionId,
  onSessionChange,
  onRefresh,
  onOpenApiKeyModal,
  hasApiKey,
  refreshing = false,
}) => {
  const [editingSession, setEditingSession] = useState(false);
  const [sessionInput, setSessionInput] = useState(activeSessionId);

  const handleSessionSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (sessionInput.trim()) {
      onSessionChange(sessionInput.trim());
      setEditingSession(false);
    }
  };

  const isHealthy = health?.status === 'HEALTHY';

  return (
    <header className="top-bar">
      {/* Left: Active Session Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {editingSession ? (
          <form onSubmit={handleSessionSubmit} style={{ display: 'flex', gap: '8px' }}>
            <input
              type="text"
              className="form-input"
              style={{ width: '300px', padding: '4px 8px', fontSize: '0.8rem' }}
              value={sessionInput}
              onChange={(e) => setSessionInput(e.target.value)}
              placeholder="Enter Session UUID..."
              autoFocus
            />
            <button type="submit" className="btn btn-primary" style={{ padding: '4px 10px', fontSize: '0.75rem' }}>
              Set
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              style={{ padding: '4px 10px', fontSize: '0.75rem' }}
              onClick={() => setEditingSession(false)}
            >
              Cancel
            </button>
          </form>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Session:</span>
            {activeSessionId ? (
              <span
                onClick={() => setEditingSession(true)}
                className="font-mono"
                style={{
                  fontSize: '0.85rem',
                  color: 'var(--text-primary)',
                  cursor: 'pointer',
                  backgroundColor: 'var(--bg-tertiary)',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  border: '1px solid var(--border-subtle)',
                }}
                title="Click to change session"
              >
                {activeSessionId}
              </span>
            ) : (
              <button
                className="btn btn-secondary"
                style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                onClick={() => setEditingSession(true)}
              >
                + Set Active Session
              </button>
            )}
          </div>
        )}
      </div>

      {/* Right: Badges & Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        {/* Air-Gap Badge */}
        <span
          className="badge"
          style={{
            backgroundColor: 'rgba(59, 130, 246, 0.15)',
            color: '#60a5fa',
            border: '1px solid rgba(59, 130, 246, 0.3)',
          }}
          title="Operating in 100% disconnected offline mode"
        >
          <Radio size={12} /> AIR-GAP ACTIVE
        </span>

        {/* Health Status */}
        {health ? (
          <span
            className={`badge ${isHealthy ? 'badge-accept' : 'badge-quarantine'}`}
            title={`Database: ${health.database.accessible ? 'OK' : 'FAIL'} | Ledger: ${
              health.audit_chain.intact ? 'INTACT' : 'TAMPERED'
            }`}
          >
            {isHealthy ? <Shield size={12} /> : <ShieldAlert size={12} />}
            {health.status}
          </span>
        ) : (
          <span className="badge badge-info">CONNECTING...</span>
        )}

        {/* Version Badge */}
        {version && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }} className="font-mono">
            v{version.version}
          </span>
        )}

        {/* API Key Modal Trigger */}
        <button
          className="btn btn-secondary"
          style={{
            padding: '6px 12px',
            fontSize: '0.8rem',
            color: hasApiKey ? '#10b981' : 'var(--text-secondary)',
          }}
          onClick={onOpenApiKeyModal}
          title={hasApiKey ? 'API Key Configured' : 'Configure API Key'}
        >
          <Key size={14} />
          {hasApiKey ? 'Auth Active' : 'API Key'}
        </button>

        {/* Refresh Button */}
        <button
          className="btn btn-secondary"
          style={{ padding: '6px 10px' }}
          onClick={onRefresh}
          disabled={refreshing}
          title="Refresh Current View"
        >
          <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
        </button>
      </div>
    </header>
  );
};
