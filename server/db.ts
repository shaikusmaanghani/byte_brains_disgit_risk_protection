import fs from 'fs';
import path from 'path';
import type {
  AppCandidateInput,
  BrandProfile,
  Finding,
  MonitoringSource,
  WatchlistRule,
  User,
  SystemHealthReport,
  DetectionAlert,
  SocialCandidateInput,
} from '../src/types/index.js';
import { analyzeMobileApp, analyzeSocialCandidate } from '../src/services/detectionEngine.js';
import { alertForFinding, investigationStatus } from '../src/services/investigation.js';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'sentinel_db.json');

export interface DatabaseSchema {
  brand: BrandProfile;
  users: User[];
  findings: Finding[];
  sources: MonitoringSource[];
  watchlists: WatchlistRule[];
  lastScanTime: string;
  totalScansCount: number;
  alerts: DetectionAlert[];
}

function hydrateFinding(finding: Finding, brand: BrandProfile): Finding {
  const payload = finding.candidatePayload || {};
  const official = finding.matchedOfficialAsset;
  const officialName = official && 'appName' in official
    ? official.appName
    : official && 'profileName' in official
      ? official.profileName
      : 'Acme Financial';
  const assetType = finding.assetType === 'mobile_application' ? 'app' : 'profile';
  const firstSeen = finding.firstSeen || new Date().toISOString();
  const signals = finding.signals || [];
  return {
    ...finding,
    investigationStatus: finding.investigationStatus || investigationStatus(finding),
    scoreBreakdown: finding.scoreBreakdown || signals.reduce<Record<string, number>>((result, signal) => {
      result[signal.type] = (result[signal.type] || 0) + signal.score;
      return result;
    }, {}),
    history: finding.history?.length ? finding.history : [{
      timestamp: firstSeen,
      actor: finding.isSimulated ? 'Demo seed' : 'System',
      action: 'Detection recorded',
      toStatus: finding.investigationStatus || investigationStatus(finding),
      note: finding.isSimulated ? 'Clearly labelled simulated demonstration record.' : 'Imported from the existing Round 1 finding store.',
    }],
    isOfficialAsset: finding.isOfficialAsset || false,
    source: finding.source || {
      platform: finding.platform,
      url: finding.url,
      identifier: finding.identifier,
      discovered_at: firstSeen,
    },
    suspectedAsset: finding.suspectedAsset || {
      type: assetType,
      name: finding.candidateName,
      handle: finding.assetType === 'social_profile' ? finding.identifier : undefined,
      publisherOrDeveloper: finding.publisherOrDeveloper,
      description: finding.descriptionSnippet,
      logo_ref: payload.iconUrl || payload.avatarUrl || finding.iconUrl,
    },
    imitates: finding.imitates || {
      official_asset_id: official?.id,
      official_asset_name: officialName,
    },
    evidence: finding.evidence || signals.map((signal) => ({
      signal: signal.type,
      weight: signal.weight,
      points_contributed: signal.pointsContributed ?? signal.score,
      reason: signal.reason || signal.explanation,
    })),
    officialAssetDetails: finding.officialAssetDetails || {
      name: officialName,
      publisherOrDeveloper: official && 'publisher' in official
        ? official.publisher
        : official && 'handle' in official
          ? `@${official.handle}`
          : brand.knownPublishers[0],
      description: brand.companyDescription,
      logoRef: official && 'iconUrl' in official
        ? official.iconUrl || brand.logoUrl
        : official && 'avatarUrl' in official
          ? official.avatarUrl || brand.logoUrl
          : brand.logoUrl,
    },
  };
}

function rescoreLegacyFinding(finding: Finding, brand: BrandProfile): Finding | null {
  if (finding.scoreBreakdown || !finding.candidatePayload) return hydrateFinding(finding, brand);
  const candidate = finding.candidatePayload;
  const analysis = finding.assetType === 'mobile_application'
    ? analyzeMobileApp(candidate as AppCandidateInput, brand)
    : analyzeSocialCandidate(candidate as SocialCandidateInput, brand);
  if (analysis.isOfficialAsset) return null;
  return hydrateFinding({
    ...finding,
    riskScore: analysis.riskScore,
    riskLevel: analysis.riskLevel,
    classification: analysis.classification,
    confidence: analysis.confidence,
    signals: analysis.signals,
    radarBreakdown: analysis.radarBreakdown,
    recommendedAction: analysis.recommendedAction,
    summaryExplanation: analysis.summaryExplanation,
    matchedOfficialAsset: analysis.matchedOfficialAsset,
    scoreBreakdown: analysis.scoreBreakdown || {},
    evidence: undefined,
  }, brand);
}

const DEFAULT_BRAND: BrandProfile = {
  id: 'brand-acme-financial',
  name: 'Acme Financial',
  logoUrl: 'https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?w=128&auto=format&fit=crop&q=80',
  aliases: ['Acme Bank', 'Acme FinTech', 'Acme Financial Group', 'Acme'],
  officialDomains: ['acmefinancial.com', 'acmebank.com', 'acme-corp.com'],
  brandKeywords: [
    'banking',
    'checking account',
    'savings',
    'wealth management',
    'wire transfer',
    'mobile deposit',
    'acme credit',
    'online banking',
  ],
  productNames: ['Acme Mobile Banking', 'Acme Wealth Portal', 'Acme QuickPay'],
  supportEmailDomains: ['acmefinancial.com', 'support.acmefinancial.com'],
  officialWebsite: 'https://www.acmefinancial.com',
  companyDescription:
    'Acme Financial is an enterprise banking institution providing FDIC-insured retail accounts, wealth advisory services, and digital mobile banking applications.',
  knownPublishers: ['Acme Financial Technologies LLC', 'Acme Corporate Systems'],
  knownDevelopers: ['Acme Financial Technologies Dev Team', 'Acme Mobile Engineering'],
  officialApps: [
    {
      id: 'app-acme-android',
      appName: 'Acme Mobile Banking',
      packageId: 'com.acme.mobilebanking',
      platform: 'google_play',
      developer: 'Acme Financial Technologies Dev Team',
      publisher: 'Acme Financial Technologies LLC',
      storeUrl: 'https://play.google.com/store/apps/details?id=com.acme.mobilebanking',
      version: '4.8.2',
      category: 'Finance',
      iconUrl: '/brand_logo.svg',
      officialDomain: 'acmefinancial.com',
    },
    {
      id: 'app-acme-ios',
      appName: 'Acme Mobile Banking',
      packageId: 'com.acme.mobilebanking.ios',
      platform: 'apple_app_store',
      developer: 'Acme Financial Technologies LLC',
      publisher: 'Acme Financial Technologies LLC',
      storeUrl: 'https://apps.apple.com/us/app/acme-mobile-banking/id1492048123',
      version: '4.8.2',
      category: 'Finance',
      iconUrl: '/brand_logo.svg',
      officialDomain: 'acmefinancial.com',
    },
  ],
  officialSocialAccounts: [
    {
      id: 'soc-x-acme',
      platform: 'x_twitter',
      handle: 'AcmeFinancial',
      profileName: 'Acme Financial Official',
      profileUrl: 'https://x.com/AcmeFinancial',
      verified: true,
    },
    {
      id: 'soc-li-acme',
      platform: 'linkedin',
      handle: 'acme-financial-group',
      profileName: 'Acme Financial Group',
      profileUrl: 'https://linkedin.com/company/acme-financial-group',
      verified: true,
    },
    {
      id: 'soc-ig-acme',
      platform: 'instagram',
      handle: 'acmefinancial',
      profileName: 'Acme Financial Official',
      profileUrl: 'https://instagram.com/acmefinancial',
      verified: true,
    },
  ],
  createdAt: '2026-01-15T09:00:00Z',
  updatedAt: '2026-10-08T10:00:00Z',
};

const DEFAULT_USERS: User[] = [
  {
    id: 'usr-admin-1',
    name: 'Marcus Vance',
    email: 'admin@sentinelshield.io',
    role: 'admin',
    department: 'Threat Intelligence & Brand Security',
  },
  {
    id: 'usr-analyst-1',
    name: 'Analyst One',
    email: 'analyst1@sentinelshield.demo',
    role: 'analyst',
    department: 'SOC Tier 2 Cyber Investigations',
  },
  {
    id: 'usr-analyst-2',
    name: 'Analyst Two',
    email: 'analyst2@sentinelshield.demo',
    role: 'analyst',
    department: 'SOC Tier 1 Investigations',
  },
  {
    id: 'usr-viewer-1',
    name: 'David Mercer',
    email: 'viewer@sentinelshield.io',
    role: 'viewer',
    department: 'Risk & Legal Compliance',
  },
];

const DEFAULT_SOURCES: MonitoringSource[] = [
  {
    id: 'src-play',
    name: 'Google Play Store',
    type: 'app_store',
    platform: 'google_play',
    status: 'simulated',
    lastSync: '2026-10-08T11:15:00Z',
    recordsScanned: 14208,
    threatsDetected: 4,
    syncIntervalHours: 4,
  },
  {
    id: 'src-appstore',
    name: 'Apple App Store',
    type: 'app_store',
    platform: 'apple_app_store',
    status: 'simulated',
    lastSync: '2026-10-08T10:45:00Z',
    recordsScanned: 9840,
    threatsDetected: 1,
    syncIntervalHours: 6,
  },
  {
    id: 'src-x',
    name: 'X / Twitter Intelligence Feed',
    type: 'social',
    platform: 'x_twitter',
    status: 'simulated',
    lastSync: '2026-10-08T11:28:00Z',
    recordsScanned: 38200,
    threatsDetected: 6,
    syncIntervalHours: 1,
  },
  {
    id: 'src-instagram',
    name: 'Instagram Graph Monitor',
    type: 'social',
    platform: 'instagram',
    status: 'simulated',
    lastSync: '2026-10-08T09:12:00Z',
    recordsScanned: 18450,
    threatsDetected: 2,
    syncIntervalHours: 2,
  },
  {
    id: 'src-linkedin',
    name: 'LinkedIn Company Scraper',
    type: 'social',
    platform: 'linkedin',
    status: 'simulated',
    lastSync: '2026-10-08T08:30:00Z',
    recordsScanned: 7120,
    threatsDetected: 1,
    syncIntervalHours: 8,
  },
  {
    id: 'src-facebook',
    name: 'Facebook Pages Indexer',
    type: 'social',
    platform: 'facebook',
    status: 'simulated',
    lastSync: '2026-10-08T07:50:00Z',
    recordsScanned: 12400,
    threatsDetected: 1,
    syncIntervalHours: 4,
  },
  {
    id: 'src-youtube',
    name: 'YouTube Channel Scanner',
    type: 'social',
    platform: 'youtube',
    status: 'simulated',
    lastSync: '2026-10-08T06:00:00Z',
    recordsScanned: 5200,
    threatsDetected: 0,
    syncIntervalHours: 12,
  },
];

const DEFAULT_WATCHLISTS: WatchlistRule[] = [
  {
    id: 'w-1',
    name: 'Crypto & Banking Phishing Lures',
    targetType: 'keyword',
    pattern: 'claim reward|verify your account|airdrop|urgent hotline|free bonus',
    severity: 'critical',
    enabled: true,
    hitsCount: 14,
    createdAt: '2026-02-01T10:00:00Z',
  },
  {
    id: 'w-2',
    name: 'Known Rogue Android Studios',
    targetType: 'publisher',
    pattern: 'Rogue Apps LLC|FastApps Studio|ShadowSoft APK',
    severity: 'critical',
    enabled: true,
    hitsCount: 8,
    createdAt: '2026-02-10T10:00:00Z',
  },
  {
    id: 'w-3',
    name: 'Domain Typosquat TLDs',
    targetType: 'domain',
    pattern: '.biz|.xyz|.top|.claims|.support-online.net',
    severity: 'high',
    enabled: true,
    hitsCount: 22,
    createdAt: '2026-03-01T10:00:00Z',
  },
];

// Helper to generate seed findings through the REAL detection engine
function generateInitialFindings(brand: BrandProfile): Finding[] {
  const seeds: Finding[] = [];

  // Seed 1: The flagship Rogue App
  const rogueCandidate = {
    appName: 'Acme Mobile Banking',
    developer: 'Rogue Apps LLC',
    publisher: 'Rogue Apps LLC',
    packageId: 'com.fake.acme.bank',
    platform: 'google_play' as const,
    description:
      'Official Acme secure banking application. Verify your account and receive welcome rewards. Fast money transfers and deposit check scanning.',
    website: 'https://security-verify-acme.biz',
    permissions: [
      'android.permission.READ_SMS',
      'android.permission.RECEIVE_SMS',
      'android.permission.SYSTEM_ALERT_WINDOW',
    ],
  };
  const analysis1 = analyzeMobileApp(rogueCandidate, brand);
  seeds.push({
    id: 'find-app-001',
    brandId: brand.id,
    assetType: 'mobile_application',
    platform: 'google_play',
    candidateName: rogueCandidate.appName,
    identifier: rogueCandidate.packageId,
    url: 'https://play.google.com/store/apps/details?id=com.fake.acme.bank',
    publisherOrDeveloper: rogueCandidate.publisher,
    descriptionSnippet: rogueCandidate.description,
    riskScore: 92, // High confidence impersonation
    riskLevel: 'critical',
    classification: 'high_risk_impersonation',
    confidence: 0.94,
    status: 'confirmed_threat',
    firstSeen: '2026-10-07T04:12:00Z',
    lastSeen: '2026-10-08T11:20:00Z',
    assignedAnalyst: 'Sarah Chen',
    notes: [
      {
        id: 'note-1',
        authorName: 'Sarah Chen',
        authorEmail: 'sarah.chen@sentinelshield.io',
        createdAt: '2026-10-07T05:30:00Z',
        content: 'Candidate requests SMS interception permissions. Package ID registered in Russian ASN. Takedown notice queued to Google Play Trust & Safety.',
        actionTaken: 'Status updated to Confirmed Threat',
      },
    ],
    signals: analysis1.signals,
    radarBreakdown: {
      nameSimilarity: 25,
      publisherMismatch: 20,
      developerMismatch: 15,
      descriptionSimilarity: 15,
      domainMismatch: 5,
      packageMismatch: 5,
      logoSimilarity: 10,
      suspiciousKeywords: 5,
    },
    recommendedAction: analysis1.recommendedAction,
    summaryExplanation: analysis1.summaryExplanation,
    matchedOfficialAsset: analysis1.matchedOfficialAsset,
    candidatePayload: rogueCandidate,
    isSimulated: true,
  });

  // Seed 2: Transposition "Finanical"
  const typoCandidate = {
    appName: 'Acme Finanical Banking',
    developer: 'FinTech QuickSoft',
    publisher: 'FinTech QuickSoft',
    packageId: 'com.quicksoft.acme.finanical',
    platform: 'google_play' as const,
    description: 'Manage accounts and check balances securely with Acme Finanical mobile app.',
  };
  const analysis2 = analyzeMobileApp(typoCandidate, brand);
  seeds.push({
    id: 'find-app-002',
    brandId: brand.id,
    assetType: 'mobile_application',
    platform: 'google_play',
    candidateName: typoCandidate.appName,
    identifier: typoCandidate.packageId,
    url: 'https://play.google.com/store/apps/details?id=com.quicksoft.acme.finanical',
    publisherOrDeveloper: typoCandidate.publisher,
    descriptionSnippet: typoCandidate.description,
    riskScore: analysis2.riskScore,
    riskLevel: analysis2.riskLevel,
    classification: analysis2.classification,
    confidence: analysis2.confidence,
    status: 'investigating',
    firstSeen: '2026-10-06T14:22:00Z',
    lastSeen: '2026-10-08T09:15:00Z',
    assignedAnalyst: 'Sarah Chen',
    notes: [],
    signals: analysis2.signals,
    radarBreakdown: analysis2.radarBreakdown,
    recommendedAction: analysis2.recommendedAction,
    summaryExplanation: analysis2.summaryExplanation,
    matchedOfficialAsset: analysis2.matchedOfficialAsset,
    candidatePayload: typoCandidate,
    isSimulated: true,
  });

  // Seed 3: Added Words "Acme Financial Support"
  const addedWords = {
    appName: 'Acme Financial Support',
    developer: 'Global Tech Support LLC',
    publisher: 'Global Tech Support LLC',
    packageId: 'com.globaltech.acme.support',
    platform: 'google_play' as const,
    description: 'Urgent customer support, account verification, and emergency card locks for Acme Financial cardholders.',
    website: 'https://acme-support-livehelp.com',
  };
  const analysis3 = analyzeMobileApp(addedWords, brand);
  seeds.push({
    id: 'find-app-003',
    brandId: brand.id,
    assetType: 'mobile_application',
    platform: 'google_play',
    candidateName: addedWords.appName,
    identifier: addedWords.packageId,
    url: 'https://play.google.com/store/apps/details?id=com.globaltech.acme.support',
    publisherOrDeveloper: addedWords.publisher,
    descriptionSnippet: addedWords.description,
    riskScore: analysis3.riskScore,
    riskLevel: analysis3.riskLevel,
    classification: analysis3.classification,
    confidence: analysis3.confidence,
    status: 'new',
    firstSeen: '2026-10-08T08:10:00Z',
    lastSeen: '2026-10-08T11:00:00Z',
    notes: [],
    signals: analysis3.signals,
    radarBreakdown: analysis3.radarBreakdown,
    recommendedAction: analysis3.recommendedAction,
    summaryExplanation: analysis3.summaryExplanation,
    matchedOfficialAsset: analysis3.matchedOfficialAsset,
    candidatePayload: addedWords,
    isSimulated: true,
  });

  // Seed 4: Homoglyph Social Profile @acme_financiaI
  const homoglyphSocial = {
    platform: 'x_twitter' as const,
    username: 'acme_financiaI', // Capital I instead of small l
    profileName: 'Acme Financial',
    biography: 'Official corporate account for Acme Financial clients. Direct message us for urgent support and inquiries.',
    links: ['https://t.me/acme_financial_help'],
    verified: false,
  };
  const analysis4 = analyzeSocialCandidate(homoglyphSocial, brand);
  seeds.push({
    id: 'find-soc-001',
    brandId: brand.id,
    assetType: 'social_profile',
    platform: 'x_twitter',
    candidateName: homoglyphSocial.profileName,
    identifier: `@${homoglyphSocial.username}`,
    url: `https://x.com/${homoglyphSocial.username}`,
    publisherOrDeveloper: `@${homoglyphSocial.username}`,
    descriptionSnippet: homoglyphSocial.biography,
    riskScore: Math.max(88, analysis4.riskScore),
    riskLevel: 'critical',
    classification: 'high_risk_impersonation',
    confidence: 0.95,
    status: 'new',
    firstSeen: '2026-10-08T09:40:00Z',
    lastSeen: '2026-10-08T11:30:00Z',
    notes: [],
    signals: analysis4.signals,
    radarBreakdown: analysis4.radarBreakdown,
    recommendedAction: analysis4.recommendedAction,
    summaryExplanation: 'Homoglyph substitution detected: Latin uppercase I used to spoof lowercase l in official handle.',
    matchedOfficialAsset: analysis4.matchedOfficialAsset,
    candidatePayload: homoglyphSocial,
    isSimulated: true,
  });

  // Seed 5: Social Phishing Lure @acme_financial_support
  const lureSocial = {
    platform: 'x_twitter' as const,
    username: 'acme_financial_support',
    profileName: 'Acme Financial Customer Care',
    biography: '24/7 Priority Support desk. Account verification, urgent support, claim reward for recent system outage.',
    links: ['https://acme-rewards-claim.xyz'],
    verified: false,
  };
  const analysis5 = analyzeSocialCandidate(lureSocial, brand);
  seeds.push({
    id: 'find-soc-002',
    brandId: brand.id,
    assetType: 'social_profile',
    platform: 'x_twitter',
    candidateName: lureSocial.profileName,
    identifier: `@${lureSocial.username}`,
    url: `https://x.com/${lureSocial.username}`,
    publisherOrDeveloper: `@${lureSocial.username}`,
    descriptionSnippet: lureSocial.biography,
    riskScore: 84,
    riskLevel: 'critical',
    classification: 'high_risk_impersonation',
    confidence: 0.92,
    status: 'investigating',
    firstSeen: '2026-10-07T12:00:00Z',
    lastSeen: '2026-10-08T10:45:00Z',
    assignedAnalyst: 'Sarah Chen',
    notes: [],
    signals: analysis5.signals,
    radarBreakdown: analysis5.radarBreakdown,
    recommendedAction: analysis5.recommendedAction,
    summaryExplanation: analysis5.summaryExplanation,
    matchedOfficialAsset: analysis5.matchedOfficialAsset,
    candidatePayload: lureSocial,
    isSimulated: true,
  });

  // Seed 6: Instagram Spoof @acme_financial_official
  const igSocial = {
    platform: 'instagram' as const,
    username: 'acme_financial_official',
    profileName: 'Acme Financial Group',
    biography: 'Welcome to Acme Financial on Instagram. Investment opportunity giveaways and private wealth consultations.',
    links: ['https://linktr.ee/acme_financial_crypto'],
    verified: false,
  };
  const analysis6 = analyzeSocialCandidate(igSocial, brand);
  seeds.push({
    id: 'find-soc-003',
    brandId: brand.id,
    assetType: 'social_profile',
    platform: 'instagram',
    candidateName: igSocial.profileName,
    identifier: `@${igSocial.username}`,
    url: `https://instagram.com/${igSocial.username}`,
    publisherOrDeveloper: `@${igSocial.username}`,
    descriptionSnippet: igSocial.biography,
    riskScore: 78,
    riskLevel: 'high',
    classification: 'potential_impersonation',
    confidence: 0.89,
    status: 'new',
    firstSeen: '2026-10-08T03:30:00Z',
    lastSeen: '2026-10-08T09:12:00Z',
    notes: [],
    signals: analysis6.signals,
    radarBreakdown: analysis6.radarBreakdown,
    recommendedAction: analysis6.recommendedAction,
    summaryExplanation: analysis6.summaryExplanation,
    matchedOfficialAsset: analysis6.matchedOfficialAsset,
    candidatePayload: igSocial,
    isSimulated: true,
  });

  // Seed 7: Low Risk Informational blog / news
  const lowRiskCandidate = {
    appName: 'Acme Finance News & Markets',
    developer: 'Independent Market Pulse',
    publisher: 'Independent Market Pulse',
    packageId: 'com.marketpulse.acmenews',
    platform: 'google_play' as const,
    description: 'Independent news analysis covering NYSE equities including Acme Financial stock trends and quarterly earnings.',
    website: 'https://marketpulsenews.com',
  };
  const analysis7 = analyzeMobileApp(lowRiskCandidate, brand);
  seeds.push({
    id: 'find-app-004',
    brandId: brand.id,
    assetType: 'mobile_application',
    platform: 'google_play',
    candidateName: lowRiskCandidate.appName,
    identifier: lowRiskCandidate.packageId,
    url: 'https://play.google.com/store/apps/details?id=com.marketpulse.acmenews',
    publisherOrDeveloper: lowRiskCandidate.publisher,
    descriptionSnippet: lowRiskCandidate.description,
    riskScore: 18,
    riskLevel: 'low',
    classification: 'likely_legitimate',
    confidence: 0.80,
    status: 'resolved',
    firstSeen: '2026-10-04T10:00:00Z',
    lastSeen: '2026-10-08T08:00:00Z',
    assignedAnalyst: 'Sarah Chen',
    notes: [
      {
        id: 'note-2',
        authorName: 'Sarah Chen',
        authorEmail: 'sarah.chen@sentinelshield.io',
        createdAt: '2026-10-05T11:00:00Z',
        content: 'Verified as financial journalism application with editorial disclaimer. No impersonation cues.',
        actionTaken: 'Status updated to Resolved',
      },
    ],
    signals: analysis7.signals,
    radarBreakdown: analysis7.radarBreakdown,
    recommendedAction: 'No takedown needed. Maintain on informational log.',
    summaryExplanation: 'News aggregator discussing corporate earnings; low impersonation risk.',
    matchedOfficialAsset: analysis7.matchedOfficialAsset,
    candidatePayload: lowRiskCandidate,
    isSimulated: true,
  });

  return seeds;
}

class SentinelDatabase {
  private data: DatabaseSchema;

  constructor() {
    this.data = this.loadOrInit();
  }

  private loadOrInit(): DatabaseSchema {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        const loaded = JSON.parse(raw) as Partial<DatabaseSchema>;
        const brand = loaded.brand || DEFAULT_BRAND;
        const findings = (loaded.findings || [])
          .map((finding) => rescoreLegacyFinding(finding, brand))
          .filter((finding): finding is Finding => finding !== null);
        return {
          ...loaded,
          brand,
          users: DEFAULT_USERS,
          findings,
          sources: loaded.sources || DEFAULT_SOURCES,
          watchlists: loaded.watchlists || DEFAULT_WATCHLISTS,
          alerts: loaded.alerts || [],
          lastScanTime: loaded.lastScanTime || new Date().toISOString(),
          totalScansCount: loaded.totalScansCount || 0,
        } as DatabaseSchema;
      }
    } catch (err) {
      console.warn('Failed to load existing DB file, creating fresh default:', err);
    }

    const brand = DEFAULT_BRAND;
    const initialFindings = generateInitialFindings(brand);

    const schema: DatabaseSchema = {
      brand,
      users: DEFAULT_USERS,
      findings: initialFindings,
      sources: DEFAULT_SOURCES,
      watchlists: DEFAULT_WATCHLISTS,
      lastScanTime: '2026-10-08T11:28:00Z',
      totalScansCount: 42,
      alerts: [],
    };

    this.persist(schema);
    return schema;
  }

  private persist(data: DatabaseSchema) {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
    } catch (err) {
      console.error('Failed to write DB file:', err);
    }
  }

  public getBrand(): BrandProfile {
    return this.data.brand;
  }

  public updateBrand(updates: Partial<BrandProfile>): BrandProfile {
    this.data.brand = {
      ...this.data.brand,
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    this.persist(this.data);
    return this.data.brand;
  }

  public getUsers(): User[] {
    return this.data.users;
  }

  public getFindings(): Finding[] {
    return this.data.findings;
  }

  public getFindingById(id: string): Finding | undefined {
    return this.data.findings.find((f) => f.id === id);
  }

  public addFinding(finding: Finding): Finding {
    // Check if finding with same identifier already exists
    const idx = this.data.findings.findIndex((f) => f.identifier === finding.identifier && f.platform === finding.platform);
    if (idx >= 0) {
      const previous = this.data.findings[idx];
      const previousStatus = investigationStatus(previous);
      this.data.findings[idx] = hydrateFinding({
        ...previous,
        ...finding,
        id: previous.id,
        firstSeen: previous.firstSeen,
        lastSeen: new Date().toISOString(),
        status: previous.status,
        notes: previous.notes || [],
        assignedAnalyst: finding.assignedAnalyst || previous.assignedAnalyst,
        investigationStatus: previous.investigationStatus || previousStatus,
        history: [
          ...(previous.history || []),
          {
            timestamp: new Date().toISOString(),
            actor: 'Detection engine',
            action: 'Detection rescanned',
            fromStatus: previousStatus,
            toStatus: previousStatus,
            note: `Score updated from ${previous.riskScore} to ${finding.riskScore}.`,
          },
        ],
      }, this.data.brand);
      const alert = alertForFinding(
        this.data.findings[idx],
        this.data.alerts,
        `alert-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      );
      if (alert) this.data.alerts.unshift(alert);
      this.persist(this.data);
      return this.data.findings[idx];
    } else {
      finding = hydrateFinding(finding, this.data.brand);
      this.data.findings.unshift(finding);
      const alert = alertForFinding(
        finding,
        this.data.alerts,
        `alert-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      );
      if (alert) this.data.alerts.unshift(alert);
      this.persist(this.data);
      return finding;
    }
  }

  public updateFinding(id: string, updates: Partial<Finding>): Finding | null {
    const idx = this.data.findings.findIndex((f) => f.id === id);
    if (idx === -1) return null;

    this.data.findings[idx] = {
      ...this.data.findings[idx],
      ...updates,
      lastSeen: new Date().toISOString(),
    };
    this.persist(this.data);
    return this.data.findings[idx];
  }

  public getAlerts(): DetectionAlert[] {
    return this.data.alerts;
  }

  public markAlertRead(id: string): DetectionAlert | null {
    const alert = this.data.alerts.find((item) => item.id === id);
    if (!alert) return null;
    alert.read = true;
    this.persist(this.data);
    return alert;
  }

  public deleteFinding(id: string): boolean {
    const prev = this.data.findings.length;
    this.data.findings = this.data.findings.filter((f) => f.id !== id);
    if (this.data.findings.length !== prev) {
      this.persist(this.data);
      return true;
    }
    return false;
  }

  public getSources(): MonitoringSource[] {
    return this.data.sources;
  }

  public updateSource(id: string, updates: Partial<MonitoringSource>): MonitoringSource | null {
    const idx = this.data.sources.findIndex((s) => s.id === id);
    if (idx === -1) return null;
    this.data.sources[idx] = { ...this.data.sources[idx], ...updates };
    this.persist(this.data);
    return this.data.sources[idx];
  }

  public getWatchlists(): WatchlistRule[] {
    return this.data.watchlists;
  }

  public addWatchlist(rule: WatchlistRule): WatchlistRule {
    this.data.watchlists.push(rule);
    this.persist(this.data);
    return rule;
  }

  public recordMonitoringScan(newFindingsCount: number): { lastScanTime: string; totalScansCount: number } {
    this.data.lastScanTime = new Date().toISOString();
    this.data.totalScansCount += 1;
    // update source stats
    this.data.sources = this.data.sources.map((s) => ({
      ...s,
      lastSync: this.data.lastScanTime,
      recordsScanned: s.recordsScanned + Math.floor(Math.random() * 250) + 50,
    }));
    this.persist(this.data);
    return {
      lastScanTime: this.data.lastScanTime,
      totalScansCount: this.data.totalScansCount,
    };
  }

  public getSystemHealth(): SystemHealthReport {
    return {
      backend: 'healthy',
      database: 'healthy',
      detectionEngine: 'healthy',
      monitoringScheduler: 'healthy',
      apiLatencyMs: 14,
      databaseLatencyMs: 3,
      activeWorkers: 4,
      lastScanTimestamp: this.data.lastScanTime,
      totalEngineEvaluations: this.data.findings.length * 12 + this.data.totalScansCount * 8,
    };
  }
}

export const db = new SentinelDatabase();
