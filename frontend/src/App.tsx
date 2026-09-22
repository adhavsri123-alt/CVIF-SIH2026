import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { TopBar } from './components/layout/TopBar';
import { ApiKeyModal } from './components/common/ApiKeyModal';
import { OverviewPage } from './pages/OverviewPage';
import { DatasetPage } from './pages/DatasetPage';
import { ModelPage } from './pages/ModelPage';
import { ProvenancePage } from './pages/ProvenancePage';
import { ShiftPage } from './pages/ShiftPage';
import { AssurancePage } from './pages/AssurancePage';
import { EvidencePage } from './pages/EvidencePage';
import { AuditPage } from './pages/AuditPage';
import { LineagePage } from './pages/LineagePage';
import { HealthStatusResponse, VersionResponse } from './types/api';
import api from './api/client';

export const App: React.FC = () => {
  // Determine initial tab from pathname or default to overview
  const getInitialTab = (): string => {
    const path = window.location.pathname.replace(/^\/+/, '');
    const validTabs = ['overview', 'dataset', 'model', 'provenance', 'shift', 'lineage', 'assurance', 'evidence', 'audit'];
    if (validTabs.includes(path)) {
      return path;
    }
    return 'overview';
  };

  const [activeTab, setActiveTab] = useState<string>(getInitialTab());
  const [activeSessionId, setActiveSessionId] = useState<string>(() => {
    try {
      return sessionStorage.getItem('cvif_active_session') || '';
    } catch {
      return '';
    }
  });

  const [health, setHealth] = useState<HealthStatusResponse | null>(null);
  const [version, setVersion] = useState<VersionResponse | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [apiKeyModalOpen, setApiKeyModalOpen] = useState(false);
  const [apiKey, setApiKey] = useState<string | null>(api.getApiKey());

  // Listen to browser popstate (back/forward)
  useEffect(() => {
    const handlePopState = () => {
      setActiveTab(getInitialTab());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Fetch initial telemetry
  useEffect(() => {
    loadSystemTelemetry();
  }, []);

  const loadSystemTelemetry = async () => {
    setRefreshing(true);
    try {
      const [h, v] = await Promise.all([api.getHealth(), api.getVersion()]);
      setHealth(h);
      setVersion(v);
    } catch {
      // API may be initializing
    } finally {
      setRefreshing(false);
    }
  };

  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
    const newPath = tab === 'overview' ? '/' : `/${tab}`;
    if (window.location.pathname !== newPath) {
      window.history.pushState({}, '', newPath);
    }
  };

  const handleSessionChange = (sessionId: string) => {
    setActiveSessionId(sessionId);
    try {
      sessionStorage.setItem('cvif_active_session', sessionId);
    } catch {
      // Ignore
    }
  };

  const handleSaveApiKey = (key: string | null) => {
    api.setApiKey(key);
    setApiKey(key);
    loadSystemTelemetry();
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <Sidebar activeTab={activeTab} onTabChange={handleTabChange} />

      {/* Main Content Area */}
      <div className="main-content">
        <TopBar
          health={health}
          version={version}
          activeSessionId={activeSessionId}
          onSessionChange={handleSessionChange}
          onRefresh={loadSystemTelemetry}
          onOpenApiKeyModal={() => setApiKeyModalOpen(true)}
          hasApiKey={Boolean(apiKey)}
          refreshing={refreshing}
        />

        <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          {activeTab === 'overview' && (
            <OverviewPage
              activeSessionId={activeSessionId}
              onNavigate={handleTabChange}
            />
          )}

          {activeTab === 'dataset' && (
            <DatasetPage
              activeSessionId={activeSessionId}
              onSessionCreated={handleSessionChange}
            />
          )}

          {activeTab === 'model' && (
            <ModelPage
              activeSessionId={activeSessionId}
              onSessionCreated={handleSessionChange}
            />
          )}

          {activeTab === 'provenance' && <ProvenancePage />}

          {activeTab === 'shift' && (
            <ShiftPage
              activeSessionId={activeSessionId}
              onSessionCreated={handleSessionChange}
            />
          )}

          {activeTab === 'lineage' && (
            <LineagePage
              activeSessionId={activeSessionId}
              onNavigate={handleTabChange}
            />
          )}

          {activeTab === 'assurance' && (
            <AssurancePage activeSessionId={activeSessionId} />
          )}

          {activeTab === 'evidence' && (
            <EvidencePage activeSessionId={activeSessionId} />
          )}

          {activeTab === 'audit' && <AuditPage />}
        </main>
      </div>

      {/* API Key Modal */}
      <ApiKeyModal
        isOpen={apiKeyModalOpen}
        onClose={() => setApiKeyModalOpen(false)}
        currentKey={apiKey}
        onSaveKey={handleSaveApiKey}
      />
    </div>
  );
};

export default App;
