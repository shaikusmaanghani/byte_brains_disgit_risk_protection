import {
  BrandProfile,
  Finding,
  MonitoringSource,
  WatchlistRule,
  User,
  AppCandidateInput,
  SocialCandidateInput,
  AnalysisResult,
  SystemHealthReport,
  ThreatGraphNode,
  ThreatGraphLink,
} from '../types';

const BASE_URL = '/api';

export const apiClient = {
  // Auth
  async login(email?: string): Promise<{ token: string; user: User; expiresAt: string }> {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) throw new Error('Authentication failed');
    return res.json();
  },

  // Brand Profile
  async getProfile(): Promise<BrandProfile> {
    const res = await fetch(`${BASE_URL}/profile`);
    if (!res.ok) throw new Error('Failed to fetch brand profile');
    return res.json();
  },

  async updateProfile(updates: Partial<BrandProfile>): Promise<BrandProfile> {
    const res = await fetch(`${BASE_URL}/profile`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!res.ok) throw new Error('Failed to update brand profile');
    return res.json();
  },

  // Findings
  async getFindings(filters?: {
    search?: string;
    platform?: string;
    assetType?: string;
    risk?: string;
    status?: string;
    sort?: string;
  }): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (filters?.search) params.append('search', filters.search);
    if (filters?.platform) params.append('platform', filters.platform);
    if (filters?.assetType) params.append('assetType', filters.assetType);
    if (filters?.risk) params.append('risk', filters.risk);
    if (filters?.status) params.append('status', filters.status);
    if (filters?.sort) params.append('sort', filters.sort);

    const query = params.toString() ? `?${params.toString()}` : '';
    const res = await fetch(`${BASE_URL}/findings${query}`);
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  async getFindingById(id: string): Promise<Finding> {
    const res = await fetch(`${BASE_URL}/findings/${id}`);
    if (!res.ok) throw new Error('Finding not found');
    return res.json();
  },

  async updateFinding(
    id: string,
    updates: Partial<Finding> & { newNote?: { content: string; actionTaken?: string; authorName?: string } }
  ): Promise<Finding> {
    const res = await fetch(`${BASE_URL}/findings/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!res.ok) throw new Error('Failed to update finding');
    return res.json();
  },

  async deleteFinding(id: string): Promise<void> {
    const res = await fetch(`${BASE_URL}/findings/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete finding');
  },

  // Analysis
  async analyzeApp(candidate: AppCandidateInput): Promise<AnalysisResult> {
    const res = await fetch(`${BASE_URL}/analyze/app`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(candidate),
    });
    if (!res.ok) throw new Error('Analysis request failed');
    return res.json();
  },

  async analyzeSocial(candidate: SocialCandidateInput): Promise<AnalysisResult> {
    const res = await fetch(`${BASE_URL}/analyze/social`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(candidate),
    });
    if (!res.ok) throw new Error('Analysis request failed');
    return res.json();
  },

  async createFindingFromCandidate(payload: Record<string, any>): Promise<Finding> {
    const res = await fetch(`${BASE_URL}/findings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('Failed to record candidate finding');
    return res.json();
  },

  // Monitoring
  async runMonitoringScan(): Promise<{
    success: boolean;
    message: string;
    scannedSources: number;
    threatsIdentified: number;
    lastScanTime: string;
    totalScansCount: number;
  }> {
    const res = await fetch(`${BASE_URL}/monitoring/run`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to run monitoring scan');
    return res.json();
  },

  // Analytics
  async getAnalyticsOverview(): Promise<any> {
    const res = await fetch(`${BASE_URL}/analytics/overview`);
    if (!res.ok) throw new Error('Failed to fetch analytics overview');
    return res.json();
  },

  async getAnalyticsTrends(): Promise<any> {
    const res = await fetch(`${BASE_URL}/analytics/trends`);
    if (!res.ok) throw new Error('Failed to fetch analytics trends');
    return res.json();
  },

  // Sources & Watchlists
  async getSources(): Promise<MonitoringSource[]> {
    const res = await fetch(`${BASE_URL}/sources`);
    if (!res.ok) throw new Error('Failed to fetch sources');
    return res.json();
  },

  async getWatchlists(): Promise<WatchlistRule[]> {
    const res = await fetch(`${BASE_URL}/watchlists`);
    if (!res.ok) throw new Error('Failed to fetch watchlists');
    return res.json();
  },

  async createWatchlist(rule: Partial<WatchlistRule>): Promise<WatchlistRule> {
    const res = await fetch(`${BASE_URL}/watchlists`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    if (!res.ok) throw new Error('Failed to create watchlist');
    return res.json();
  },

  // Threat Graph
  async getThreatGraph(): Promise<{ nodes: ThreatGraphNode[]; links: ThreatGraphLink[] }> {
    const res = await fetch(`${BASE_URL}/threat-graph`);
    if (!res.ok) throw new Error('Failed to load threat graph');
    return res.json();
  },

  // System Health
  async getSystemHealth(): Promise<SystemHealthReport> {
    const res = await fetch(`${BASE_URL}/system/health`);
    if (!res.ok) throw new Error('Failed to fetch system health');
    return res.json();
  },
};
