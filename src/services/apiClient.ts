import {
  BrandProfile,
  Finding,
  MonitoringSource,
  WatchlistRule,
  User,
  InvestigationStatus,
  DetectionAlert,
  AppCandidateInput,
  SocialCandidateInput,
  AnalysisResult,
  SystemHealthReport,
  ThreatGraphNode,
  ThreatGraphLink,
} from '../types';

const BASE_URL = '/api';

async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  const token = sessionStorage.getItem('sentinel-token');
  if (token && !String(input).endsWith('/auth/login')) headers.set('Authorization', `Bearer ${token}`);
  return fetch(input, { ...init, headers });
}

export const apiClient = {
  // Auth
  async login(email: string, password: string): Promise<{ token: string; user: User; expiresAt: string }> {
    const res = await apiFetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) throw new Error('Authentication failed');
    const session = await res.json();
    sessionStorage.setItem('sentinel-token', session.token);
    return session;
  },

  async logout(): Promise<void> {
    const res = await apiFetch(`${BASE_URL}/auth/logout`, { method: 'POST' });
    sessionStorage.removeItem('sentinel-token');
    if (!res.ok) throw new Error('Failed to end demo session');
  },

  async getCurrentUser(): Promise<User> {
    const res = await apiFetch(`${BASE_URL}/auth/me`);
    if (!res.ok) throw new Error('Demo session is no longer valid');
    return res.json();
  },

  // Brand Profile
  async getProfile(): Promise<BrandProfile> {
    const res = await apiFetch(`${BASE_URL}/profile`);
    if (!res.ok) throw new Error('Failed to fetch brand profile');
    return res.json();
  },

  async updateProfile(updates: Partial<BrandProfile>): Promise<BrandProfile> {
    const res = await apiFetch(`${BASE_URL}/profile`, {
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
    const res = await apiFetch(`${BASE_URL}/findings${query}`);
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  async getFindingById(id: string): Promise<Finding> {
    const res = await apiFetch(`${BASE_URL}/findings/${id}`);
    if (!res.ok) throw new Error('Finding not found');
    return res.json();
  },

  async updateFinding(
    id: string,
    updates: Partial<Finding> & { newNote?: { content: string; actionTaken?: string; authorName?: string } }
  ): Promise<Finding> {
    const res = await apiFetch(`${BASE_URL}/findings/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!res.ok) throw new Error('Failed to update finding');
    return res.json();
  },

  async transitionFinding(id: string, status: InvestigationStatus, note: string): Promise<Finding> {
    const res = await apiFetch(`${BASE_URL}/findings/${id}/investigate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, note }),
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Failed to update investigation status');
    return res.json();
  },

  async draftTakedownReport(id: string): Promise<string> {
    const res = await apiFetch(`${BASE_URL}/findings/${id}/report`, { method: 'POST' });
    if (!res.ok) throw new Error((await res.json()).error || 'Failed to draft takedown report');
    return (await res.json()).report;
  },

  async getAlerts(): Promise<DetectionAlert[]> {
    const res = await apiFetch(`${BASE_URL}/alerts`);
    if (!res.ok) throw new Error('Failed to load alerts');
    return res.json();
  },

  async markAlertRead(id: string): Promise<DetectionAlert> {
    const res = await apiFetch(`${BASE_URL}/alerts/${id}/read`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to mark alert as read');
    return res.json();
  },

  async askAnalystAssistant(question: string): Promise<string> {
    const res = await apiFetch(`${BASE_URL}/assistant/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    });
    if (!res.ok) throw new Error('Assistant request failed');
    return (await res.json()).answer;
  },

  async deleteFinding(id: string): Promise<void> {
    const res = await apiFetch(`${BASE_URL}/findings/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete finding');
  },

  // Analysis
  async analyzeApp(candidate: AppCandidateInput): Promise<AnalysisResult> {
    const res = await apiFetch(`${BASE_URL}/analyze/app`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(candidate),
    });
    if (!res.ok) throw new Error('Analysis request failed');
    return res.json();
  },

  async analyzeSocial(candidate: SocialCandidateInput): Promise<AnalysisResult> {
    const res = await apiFetch(`${BASE_URL}/analyze/social`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(candidate),
    });
    if (!res.ok) throw new Error('Analysis request failed');
    return res.json();
  },

  async createFindingFromCandidate(payload: Record<string, any>): Promise<Finding> {
    const res = await apiFetch(`${BASE_URL}/findings`, {
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
    const res = await apiFetch(`${BASE_URL}/monitoring/run`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to run monitoring scan');
    return res.json();
  },

  // Analytics
  async getAnalyticsOverview(): Promise<any> {
    const res = await apiFetch(`${BASE_URL}/analytics/overview`);
    if (!res.ok) throw new Error('Failed to fetch analytics overview');
    return res.json();
  },

  async getAnalyticsTrends(): Promise<any> {
    const res = await apiFetch(`${BASE_URL}/analytics/trends`);
    if (!res.ok) throw new Error('Failed to fetch analytics trends');
    return res.json();
  },

  // Sources & Watchlists
  async getSources(): Promise<MonitoringSource[]> {
    const res = await apiFetch(`${BASE_URL}/sources`);
    if (!res.ok) throw new Error('Failed to fetch sources');
    return res.json();
  },

  async getWatchlists(): Promise<WatchlistRule[]> {
    const res = await apiFetch(`${BASE_URL}/watchlists`);
    if (!res.ok) throw new Error('Failed to fetch watchlists');
    return res.json();
  },

  async createWatchlist(rule: Partial<WatchlistRule>): Promise<WatchlistRule> {
    const res = await apiFetch(`${BASE_URL}/watchlists`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    if (!res.ok) throw new Error('Failed to create watchlist');
    return res.json();
  },

  // Threat Graph
  async getThreatGraph(): Promise<{ nodes: ThreatGraphNode[]; links: ThreatGraphLink[] }> {
    const res = await apiFetch(`${BASE_URL}/threat-graph`);
    if (!res.ok) throw new Error('Failed to load threat graph');
    return res.json();
  },

  // System Health
  async getSystemHealth(): Promise<SystemHealthReport> {
    const res = await apiFetch(`${BASE_URL}/system/health`);
    if (!res.ok) throw new Error('Failed to fetch system health');
    return res.json();
  },
};
