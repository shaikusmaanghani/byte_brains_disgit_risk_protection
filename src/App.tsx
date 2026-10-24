/**
 * SentinelShield — Digital Risk Protection
 * Production Cyber Security Operations Center (SOC) Application
 */

import React, { useEffect, useRef, useState } from 'react';
import { Header } from './components/Header';
import { Sidebar, PageId } from './components/Sidebar';
import { ThreatDetailModal } from './components/ThreatDetailModal';
import { MonitoringScanModal } from './components/MonitoringScanModal';

import { Dashboard } from './pages/Dashboard';
import { ThreatFindings } from './pages/ThreatFindings';
import { BrandTwinScanner } from './pages/BrandTwinScanner';
import { ThreatGraph } from './components/ThreatGraph';
import { SocialMonitoring } from './pages/SocialMonitoring';
import { AppMonitoring } from './pages/AppMonitoring';
import { BrandProfilePage } from './pages/BrandProfilePage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { WatchlistsPage } from './pages/WatchlistsPage';
import { DataSourcesPage } from './pages/DataSourcesPage';
import { ReportsPage } from './pages/ReportsPage';
import { ArchitecturePage } from './pages/ArchitecturePage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { DemoLoginPage } from './pages/DemoLoginPage';
import { AnalystChatPanel } from './components/AnalystChatPanel';

import { apiClient } from './services/apiClient';
import {
  BrandProfile,
  Finding,
  MonitoringSource,
  WatchlistRule,
  User,
  FindingStatus,
  ThreatGraphNode,
  ThreatGraphLink,
  DetectionAlert,
} from './types';

export default function App() {
  const [activePage, setActivePage] = useState<PageId>('dashboard');
  const [currentUser, setCurrentUser] = useState<User | null>(null);

  const [brand, setBrand] = useState<BrandProfile | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sources, setSources] = useState<MonitoringSource[]>([]);
  const [watchlists, setWatchlists] = useState<WatchlistRule[]>([]);
  const [threatGraph, setThreatGraph] = useState<{ nodes: ThreatGraphNode[]; links: ThreatGraphLink[] }>({
    nodes: [],
    links: [],
  });
  const [overview, setOverview] = useState<any>(null);
  const [trends, setTrends] = useState<any>(null);
  const [alerts, setAlerts] = useState<DetectionAlert[]>([]);
  const [alertToast, setAlertToast] = useState('');
  const [loadError, setLoadError] = useState('');
  const knownAlertIds = useRef<Set<string>>(new Set());
  const hasLoadedAlerts = useRef(false);

  // Modals & Active state
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isScanningModalOpen, setIsScanningModalOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  const loadAllData = async () => {
    try {
      setLoadError('');
      const [
        profileRes,
        findingsRes,
        sourcesRes,
        watchlistsRes,
        overviewRes,
        trendsRes,
        graphRes,
        alertsRes,
      ] = await Promise.all([
        apiClient.getProfile(),
        apiClient.getFindings(),
        apiClient.getSources(),
        apiClient.getWatchlists(),
        apiClient.getAnalyticsOverview(),
        apiClient.getAnalyticsTrends(),
        apiClient.getThreatGraph(),
        apiClient.getAlerts(),
      ]);

      setBrand(profileRes);
      setFindings(findingsRes);
      setSources(sourcesRes);
      setWatchlists(watchlistsRes);
      setOverview(overviewRes);
      setTrends(trendsRes);
      setThreatGraph(graphRes);
      if (hasLoadedAlerts.current) {
        const newAlerts = alertsRes.filter((alert) => !knownAlertIds.current.has(alert.id));
        if (newAlerts.length) {
          setAlertToast(`${newAlerts.length} new high-risk alert${newAlerts.length === 1 ? '' : 's'} created.`);
          window.setTimeout(() => setAlertToast(''), 5000);
        }
      }
      knownAlertIds.current = new Set(alertsRes.map((alert) => alert.id));
      hasLoadedAlerts.current = true;
      setAlerts(alertsRes);
    } catch (err) {
      console.error('Failed to load initial data:', err);
      setLoadError(err instanceof Error ? err.message : 'Could not load investigation data.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!sessionStorage.getItem('sentinel-token')) {
      setIsLoading(false);
      return;
    }
    apiClient.getCurrentUser()
      .then((user) => {
        setCurrentUser(user);
        return loadAllData();
      })
      .catch(() => {
        sessionStorage.removeItem('sentinel-token');
        setIsLoading(false);
      });
  }, []);

  const handleLogin = async (user: User) => {
    setIsLoading(true);
    setCurrentUser(user);
    await loadAllData();
  };

  const handleLogout = async () => {
    try {
      await apiClient.logout();
    } finally {
      setCurrentUser(null);
      setBrand(null);
      setFindings([]);
      setAlerts([]);
      setIsLoading(false);
    }
  };

  const handleUpdateStatus = async (id: string, status: FindingStatus, reason = `Analyst decision: ${status.replace(/_/g, ' ')}.`) => {
    try {
      const statusMap: Record<FindingStatus, import('./types').InvestigationStatus> = {
        new: 'New',
        investigating: 'Under Review',
        confirmed_threat: 'Confirmed',
        false_positive: 'False Positive',
        resolved: 'Closed',
        dismissed: 'Closed',
      };
      const updated = await apiClient.transitionFinding(id, statusMap[status], reason);
      setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
      if (selectedFinding?.id === id) {
        setSelectedFinding(updated);
      }
      // Refresh analytics
      apiClient.getAnalyticsOverview().then(setOverview);
    } catch (err) {
      console.error('Status update failed:', err);
      throw err;
    }
  };

  const handleAddNote = async (id: string, content: string, actionTaken?: string) => {
    try {
      const updated = await apiClient.updateFinding(id, {
        newNote: {
          content,
          actionTaken,
        },
      });
      setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
      if (selectedFinding?.id === id) {
        setSelectedFinding(updated);
      }
    } catch (err) {
      console.error('Note add failed:', err);
    }
  };

  const handleAssignAnalyst = async (id: string, analystName: string) => {
    try {
      const updated = await apiClient.updateFinding(id, { assignedAnalyst: analystName });
      setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
      if (selectedFinding?.id === id) {
        setSelectedFinding(updated);
      }
    } catch (err) {
      console.error('Analyst assign failed:', err);
    }
  };

  const handleReadAlert = async (alert: DetectionAlert) => {
    if (alert.read) return;
    try {
      const updated = await apiClient.markAlertRead(alert.id);
      setAlerts((previous) => previous.map((item) => item.id === updated.id ? updated : item));
    } catch (error) {
      console.error('Failed to mark alert as read:', error);
    }
  };

  const handleDraftReport = async (id: string) => {
    const report = await apiClient.draftTakedownReport(id);
    const updated = await apiClient.getFindingById(id);
    setFindings((previous) => previous.map((item) => item.id === id ? updated : item));
    setSelectedFinding(updated);
    return report;
  };

  const handleUpdateBrand = async (updates: Partial<BrandProfile>) => {
    const updated = await apiClient.updateProfile(updates);
    setBrand(updated);
    loadAllData();
  };

  const handleCreateWatchlist = async (rule: Partial<WatchlistRule>) => {
    const created = await apiClient.createWatchlist(rule);
    setWatchlists((prev) => [...prev, created]);
  };

  if (!isLoading && !currentUser) return <DemoLoginPage onLogin={handleLogin} />;

  if (loadError && !isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center p-6">
        <div className="max-w-md rounded-xl border border-rose-500/30 bg-slate-900 p-6">
          <h1 className="text-lg font-bold">Unable to load workspace</h1>
          <p role="alert" className="mt-2 text-sm text-rose-200">{loadError}</p>
          <button onClick={() => void loadAllData()} className="mt-4 rounded bg-cyan-600 px-4 py-2 text-sm font-semibold">Retry</button>
        </div>
      </div>
    );
  }

  if (isLoading || !brand || !currentUser) {
    return (
      <div className="h-screen w-screen bg-slate-950 flex flex-col items-center justify-center space-y-4">
        <div className="w-10 h-10 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
        <div className="text-xs font-mono tracking-widest text-slate-400 uppercase">
          Initializing SentinelShield Security Operations Center...
        </div>
      </div>
    );
  }

  const threatCounts = {
    critical: findings.filter((f) => f.riskLevel === 'critical' && f.status !== 'resolved').length,
    high: findings.filter((f) => f.riskLevel === 'high' && f.status !== 'resolved').length,
    active: findings.filter((f) => f.status !== 'resolved' && f.status !== 'dismissed').length,
  };

  return (
    <div className="h-screen w-screen bg-slate-950 text-slate-100 flex flex-col overflow-hidden font-sans">
      {/* Top Header */}
      <Header
        currentUser={currentUser}
        alerts={alerts}
        findings={findings}
        onLogout={handleLogout}
        onReadAlert={handleReadAlert}
        onOpenFinding={(finding) => setSelectedFinding(finding)}
        onRunScan={() => setIsScanningModalOpen(true)}
        isScanning={isScanningModalOpen}
        overallThreatLevel={overview?.overallThreatLevel || 'High'}
        lastScanTime={overview?.lastScanTime || 'Just now'}
      />

      {/* Main Workspace: Sidebar + Content */}
      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          activePage={activePage}
          onSelectPage={(p) => setActivePage(p)}
          threatCounts={threatCounts}
        />

        <main className="flex-1 overflow-y-auto bg-slate-950/90">
          {activePage === 'dashboard' && (
            <Dashboard
              overview={overview}
              trends={trends}
              findings={findings}
              brand={brand}
              onSelectFinding={(f) => setSelectedFinding(f)}
              onNavigateToScan={() => setActivePage('twin_scanner')}
              onNavigateToThreats={() => setActivePage('findings')}
              onRunScan={() => setIsScanningModalOpen(true)}
            />
          )}

          {activePage === 'findings' && (
            <ThreatFindings
              findings={findings}
              onSelectFinding={(f) => setSelectedFinding(f)}
              onRefresh={loadAllData}
              onNavigateToScan={() => setActivePage('twin_scanner')}
            />
          )}

          {activePage === 'threat_graph' && (
            <div className="p-6 space-y-6 max-w-7xl mx-auto">
              <div className="border-b border-slate-800 pb-4">
                <h1 className="text-xl font-bold text-white">Threat Relationship Graph</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Entity relationship graph depicting brand roots, authorized assets, publisher mismatch chains, and rogue targets.
                </p>
              </div>
              <ThreatGraph
                nodes={threatGraph.nodes}
                links={threatGraph.links}
                onSelectFinding={(id) => {
                  const f = findings.find((item) => item.id === id);
                  if (f) setSelectedFinding(f);
                }}
              />
            </div>
          )}

          {activePage === 'twin_scanner' && (
            <BrandTwinScanner
              brand={brand}
              onFindingSaved={() => {
                loadAllData();
                setActivePage('findings');
              }}
            />
          )}

          {activePage === 'app_monitoring' && (
            <AppMonitoring
              findings={findings}
              onSelectFinding={(f) => setSelectedFinding(f)}
              onNavigateToScan={() => setActivePage('twin_scanner')}
            />
          )}

          {activePage === 'social_monitoring' && (
            <SocialMonitoring
              findings={findings}
              onSelectFinding={(f) => setSelectedFinding(f)}
              onNavigateToScan={() => setActivePage('twin_scanner')}
            />
          )}

          {activePage === 'brand_profile' && (
            <BrandProfilePage
              brand={brand}
              onUpdateBrand={handleUpdateBrand}
            />
          )}

          {activePage === 'analytics' && (
            <AnalyticsPage
              overview={overview}
              trends={trends}
            />
          )}

          {activePage === 'watchlists' && (
            <WatchlistsPage
              watchlists={watchlists}
              onCreateWatchlist={handleCreateWatchlist}
            />
          )}

          {activePage === 'sources' && (
            <DataSourcesPage
              sources={sources}
              onRefresh={loadAllData}
            />
          )}

          {activePage === 'reports' && (
            <ReportsPage
              brand={brand}
              findings={findings}
            />
          )}

          {activePage === 'how_it_works' && <ArchitecturePage />}

          {activePage === 'system_health' && <SystemHealthPage />}
        </main>
      </div>

      {/* Investigation Modal */}
      {selectedFinding && (
        <ThreatDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onUpdateStatus={handleUpdateStatus}
          onAddNote={handleAddNote}
          onAssignAnalyst={handleAssignAnalyst}
          onDraftReport={handleDraftReport}
        />
      )}

      {/* Monitoring Scan Simulation Modal */}
      <MonitoringScanModal
        isOpen={isScanningModalOpen}
        onClose={() => setIsScanningModalOpen(false)}
        onScanCompleted={loadAllData}
      />
      <AnalystChatPanel />
      {alertToast && (
        <div role="status" className="fixed top-20 right-5 z-50 rounded-lg border border-rose-500/40 bg-rose-950 px-4 py-3 text-xs font-semibold text-rose-100 shadow-xl">
          {alertToast}
        </div>
      )}
    </div>
  );
}
