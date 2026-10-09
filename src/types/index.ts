export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type ThreatClassification =
  | 'official'
  | 'likely_legitimate'
  | 'suspicious'
  | 'potential_impersonation'
  | 'high_risk_impersonation'
  | 'unknown';

export type FindingStatus =
  | 'new'
  | 'investigating'
  | 'confirmed_threat'
  | 'false_positive'
  | 'resolved'
  | 'dismissed';

export type AssetType = 'mobile_application' | 'social_profile' | 'domain';

export type PlatformType =
  | 'google_play'
  | 'apple_app_store'
  | 'x_twitter'
  | 'instagram'
  | 'linkedin'
  | 'facebook'
  | 'youtube'
  | 'telegram'
  | 'web';

export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatarUrl?: string;
  department: string;
}

export interface OfficialApp {
  id: string;
  appName: string;
  packageId: string;
  platform: 'google_play' | 'apple_app_store';
  developer: string;
  publisher: string;
  storeUrl: string;
  version: string;
  category: string;
  iconUrl?: string;
  officialDomain?: string;
}

export interface OfficialSocialAccount {
  id: string;
  platform: PlatformType;
  handle: string;
  profileName: string;
  profileUrl: string;
  verified: boolean;
  avatarUrl?: string;
}

export interface BrandProfile {
  id: string;
  name: string;
  logoUrl: string;
  aliases: string[];
  officialDomains: string[];
  brandKeywords: string[];
  productNames: string[];
  supportEmailDomains: string[];
  officialWebsite: string;
  companyDescription: string;
  knownPublishers: string[];
  knownDevelopers: string[];
  officialApps: OfficialApp[];
  officialSocialAccounts: OfficialSocialAccount[];
  createdAt: string;
  updatedAt: string;
}

export interface DetectionSignal {
  type:
    | 'name_similarity'
    | 'username_similarity'
    | 'publisher_mismatch'
    | 'developer_mismatch'
    | 'package_mismatch'
    | 'description_similarity'
    | 'brand_keyword_similarity'
    | 'domain_mismatch'
    | 'suspicious_keywords'
    | 'logo_similarity'
    | 'homoglyph_detected'
    | 'character_swap'
    | 'verification_mismatch'
    | 'suspicious_support_links'
    | 'suspicious_permissions';
  score: number;
  weight: number;
  explanation: string;
  evidenceSnippet?: string;
  highlightDetails?: {
    candidateValue?: string;
    officialValue?: string;
    homoglyphsFound?: string[];
  };
}

export interface AppCandidateInput {
  appName: string;
  developer: string;
  publisher: string;
  packageId: string;
  description: string;
  category?: string;
  platform: 'google_play' | 'apple_app_store';
  storeUrl?: string;
  iconUrl?: string;
  version?: string;
  permissions?: string[];
  website?: string;
}

export interface SocialCandidateInput {
  platform: PlatformType;
  profileName: string;
  username: string;
  biography: string;
  profileUrl?: string;
  followerCount?: number;
  verified?: boolean;
  avatarUrl?: string;
  links?: string[];
  keywords?: string[];
}

export interface AnalysisResult {
  riskScore: number;
  riskLevel: RiskLevel;
  classification: ThreatClassification;
  confidence: number;
  isOfficialAsset: boolean;
  signals: DetectionSignal[];
  radarBreakdown: {
    nameSimilarity: number;
    publisherMismatch: number;
    developerMismatch: number;
    descriptionSimilarity: number;
    domainMismatch: number;
    packageMismatch: number;
    logoSimilarity: number;
    suspiciousKeywords: number;
  };
  recommendedAction: string;
  matchedOfficialAsset?: OfficialApp | OfficialSocialAccount | null;
  summaryExplanation: string;
}

export interface InvestigationNote {
  id: string;
  authorName: string;
  authorEmail: string;
  createdAt: string;
  content: string;
  actionTaken?: string;
}

export interface Finding {
  id: string;
  brandId: string;
  assetType: AssetType;
  platform: PlatformType;
  candidateName: string;
  identifier: string; // package ID for apps, handle for social
  url: string;
  iconUrl?: string;
  publisherOrDeveloper?: string;
  descriptionSnippet?: string;
  riskScore: number;
  riskLevel: RiskLevel;
  classification: ThreatClassification;
  confidence: number;
  status: FindingStatus;
  firstSeen: string;
  lastSeen: string;
  assignedAnalyst?: string;
  notes: InvestigationNote[];
  signals: DetectionSignal[];
  radarBreakdown: AnalysisResult['radarBreakdown'];
  recommendedAction: string;
  summaryExplanation: string;
  matchedOfficialAsset?: OfficialApp | OfficialSocialAccount | null;
  candidatePayload: Record<string, any>;
  isSimulated: boolean;
}

export interface MonitoringSource {
  id: string;
  name: string;
  type: 'social' | 'app_store';
  platform: PlatformType;
  status: 'connected' | 'simulated' | 'disconnected' | 'error';
  lastSync: string;
  recordsScanned: number;
  threatsDetected: number;
  syncIntervalHours: number;
  errorDetails?: string;
}

export interface WatchlistRule {
  id: string;
  name: string;
  targetType: 'keyword' | 'publisher' | 'developer' | 'package_id' | 'domain';
  pattern: string;
  severity: RiskLevel;
  enabled: boolean;
  hitsCount: number;
  createdAt: string;
}

export interface ThreatGraphNode {
  id: string;
  label: string;
  type: 'brand' | 'official_app' | 'official_domain' | 'official_social' | 'fake_app' | 'suspicious_publisher' | 'similar_domain' | 'suspicious_social';
  riskScore?: number;
  riskLevel?: RiskLevel;
  meta?: Record<string, any>;
}

export interface ThreatGraphLink {
  source: string;
  target: string;
  relationship: string;
  riskFlag?: boolean;
}

export interface SystemHealthReport {
  backend: 'healthy' | 'degraded' | 'down';
  database: 'healthy' | 'degraded' | 'down';
  detectionEngine: 'healthy' | 'degraded' | 'down';
  monitoringScheduler: 'healthy' | 'degraded' | 'down';
  apiLatencyMs: number;
  databaseLatencyMs: number;
  activeWorkers: number;
  lastScanTimestamp: string;
  totalEngineEvaluations: number;
}
