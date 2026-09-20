import React from 'react';
import {
  LayoutDashboard,
  Database,
  Cpu,
  FileKey,
  Activity,
  ShieldCheck,
  FileCheck2,
  Lock,
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onTabChange }) => {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'dataset', label: 'Dataset Integrity', icon: Database },
    { id: 'model', label: 'Model Integrity', icon: Cpu },
    { id: 'provenance', label: 'Inference Provenance', icon: FileKey },
    { id: 'shift', label: 'Distribution Shift', icon: Activity },
    { id: 'assurance', label: 'Assurance Assessment', icon: ShieldCheck },
    { id: 'evidence', label: 'Evidence Explorer', icon: FileCheck2 },
    { id: 'audit', label: 'Audit / System Status', icon: Lock },
  ];

  return (
    <aside className="sidebar">
      <div
        style={{
          padding: '20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}
      >
        <div
          style={{
            width: '32px',
            height: '32px',
            borderRadius: '6px',
            backgroundColor: '#3b82f6',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fff',
            fontWeight: 'bold',
          }}
        >
          C
        </div>
        <div>
          <h2 style={{ fontSize: '1.1rem', margin: 0, lineHeight: 1.2 }}>CVIF</h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Integrity Assurance
          </span>
        </div>
      </div>

      <nav style={{ padding: '16px 12px', flex: 1 }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`nav-link ${isActive ? 'active' : ''}`}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div
        style={{
          padding: '16px 20px',
          borderTop: '1px solid var(--border-subtle)',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
        }}
      >
        <span>SIH 2026 / MoD Architecture</span>
        <br />
        <span>Air-Gap Defense Protocol</span>
      </div>
    </aside>
  );
};
