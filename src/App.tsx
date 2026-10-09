/**
 * SentinelShield — Digital Risk Protection
 * Production Cyber Security Operations Center (SOC) Application
 */

import React, { useEffect, useState } from 'react';
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
} from './types';

export default function App() {
  const [activePage, setActivePage] = useState<PageId>('dashboard');
  const [currentUser, setCurrentUser] = useState<User>({
    id: 'usr-analyst-1',
    name: 'Sarah Chen',
    email: 'sarah.chen@sentinelshield.io',
    role: 'analyst',
    department: 'SOC Tier 2 Cyber Investigations',
  });

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

  // Modals & Active state
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isScanningModalOpen, setIsScanningModalOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  const loadAllData = async () => {
    try {
      const [
        profileRes,
        findingsRes,
        sourcesRes,
        watchlistsRes,
        overviewRes,
        trendsRes,
        graphRes,
      ] = await Promise.all([
        apiClient.getProfile(),
        apiClient.getFindings(),
        apiClient.getSources(),
        apiClient.getWatchlists(),
        apiClient.getAnalyticsOverview(),
        apiClient.getAnalyticsTrends(),
        apiClient.getThreatGraph(),
      ]);

      setBrand(profileRes);
      setFindings(findingsRes);
      setSources(sourcesRes);
      setWatchlists(watchlistsRes);
      setOverview(overviewRes);
      setTrends(trendsRes);
      setThreatGraph(graphRes);
    } catch (err) {
      console.error('Failed to load initial data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  const handleSwitchUser = async (role: 'admin' | 'analyst' | 'viewer') => {
    const email =
      role === 'admin'
        ? 'admin@sentinelshield.io'
        : role === 'viewer'
        ? 'viewer@sentinelshield.io'
        : 'sarah.chen@sentinelshield.io';
    try {
      const auth = await apiClient.login(email);
      setCurrentUser(auth.user);
    } catch (e) {
      console.error(e);
    }
  };

  const handleUpdateStatus = async (id: string, status: FindingStatus) => {
    try {
      const updated = await apiClient.updateFinding(id, {
        status,
        newNote: {
          content: `Analyst changed incident status to ${status.replace(/_/g, ' ')}.`,
          actionTaken: `Status set to ${status}`,
          authorName: currentUser.name,
        },
      });
      setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
      if (selectedFinding?.id === id) {
        setSelectedFinding(updated);
      }
      // Refresh analytics
      apiClient.getAnalyticsOverview().then(setOverview);
    } catch (err) {
      console.error('Status update failed:', err);
    }
  };

  const handleAddNote = async (id: string, content: string, actionTaken?: string) => {
    try {
      const updated = await apiClient.updateFinding(id, {
        newNote: {
          content,
          actionTaken,
          authorName: currentUser.name,
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

  const handleUpdateBrand = async (updates: Partial<BrandProfile>) => {
    const updated = await apiClient.updateProfile(updates);
    setBrand(updated);
    loadAllData();
  };

  const handleCreateWatchlist = async (rule: Partial<WatchlistRule>) => {
    const created = await apiClient.createWatchlist(rule);
    setWatchlists((prev) => [...prev, created]);
  };

  if (isLoading || !brand) {
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
        onSwitchUser={handleSwitchUser}
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
        />
      )}

      {/* Monitoring Scan Simulation Modal */}
      <MonitoringScanModal
        isOpen={isScanningModalOpen}
        onClose={() => setIsScanningModalOpen(false)}
        onScanCompleted={loadAllData}
      />
    </div>
  );
}
