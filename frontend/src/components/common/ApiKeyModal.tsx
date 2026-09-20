import React, { useState } from 'react';
import { Key, X } from 'lucide-react';

interface ApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentKey: string | null;
  onSaveKey: (key: string | null) => void;
}

export const ApiKeyModal: React.FC<ApiKeyModalProps> = ({
  isOpen,
  onClose,
  currentKey,
  onSaveKey,
}) => {
  const [keyInput, setKeyInput] = useState(currentKey || '');

  if (!isOpen) return null;

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    onSaveKey(keyInput.trim() ? keyInput.trim() : null);
    onClose();
  };

  const handleClear = () => {
    setKeyInput('');
    onSaveKey(null);
    onClose();
  };

  return (
    <div className="drawer-backdrop" style={{ alignItems: 'center', justifyContent: 'center' }}>
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: '480px',
          margin: '20px',
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-subtle)',
        }}
      >
        <div className="card-header">
          <div className="card-title">
            <Key size={18} style={{ color: '#3b82f6' }} />
            API Key Authentication (X-API-Key)
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer' }}
          >
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSave}>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            When API authentication is enabled in the backend (<code className="font-mono">api.api_key_enabled: true</code>),
            all protected endpoints require this key. It is stored strictly in memory/session storage for this browser tab.
          </p>

          <div className="form-group">
            <label className="form-label">Secret API Key</label>
            <input
              type="password"
              className="form-input"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              placeholder="Paste X-API-Key token here..."
              autoFocus
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
            {currentKey && (
              <button type="button" className="btn btn-secondary" onClick={handleClear}>
                Clear Key
              </button>
            )}
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Save Key
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
