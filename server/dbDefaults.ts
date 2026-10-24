import type { BrandProfile, MonitoringSource, User, WatchlistRule } from '../src/types/index.js';

export const DEFAULT_BRAND: BrandProfile = {
  id: 'brand-acme-financial',
  name: 'Acme Financial',
  logoUrl: 'https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?w=128&auto=format&fit=crop&q=80',
  aliases: ['Acme Bank', 'Acme FinTech', 'Acme Financial Group', 'Acme'],
  officialDomains: ['acmefinancial.com', 'acmebank.com', 'acme-corp.com'],
  brandKeywords: ['banking', 'checking account', 'savings', 'wealth management', 'wire transfer', 'mobile deposit', 'acme credit', 'online banking'],
  productNames: ['Acme Mobile Banking', 'Acme Wealth Portal', 'Acme QuickPay'],
  supportEmailDomains: ['acmefinancial.com', 'support.acmefinancial.com'],
  officialWebsite: 'https://www.acmefinancial.com',
  companyDescription: 'Acme Financial is an enterprise banking institution providing FDIC-insured retail accounts, wealth advisory services, and digital mobile banking applications.',
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
    { id: 'soc-x-acme', platform: 'x_twitter', handle: 'AcmeFinancial', profileName: 'Acme Financial Official', profileUrl: 'https://x.com/AcmeFinancial', verified: true },
    { id: 'soc-li-acme', platform: 'linkedin', handle: 'acme-financial-group', profileName: 'Acme Financial Group', profileUrl: 'https://linkedin.com/company/acme-financial-group', verified: true },
    { id: 'soc-ig-acme', platform: 'instagram', handle: 'acmefinancial', profileName: 'Acme Financial Official', profileUrl: 'https://instagram.com/acmefinancial', verified: true },
  ],
  createdAt: '2026-01-15T09:00:00Z',
  updatedAt: '2026-10-08T10:00:00Z',
};

export const DEFAULT_USERS: User[] = [
  { id: 'usr-admin-1', name: 'Marcus Vance', email: 'admin@sentinelshield.demo', role: 'admin', department: 'Threat Intelligence & Brand Security' },
  { id: 'usr-analyst-1', name: 'Analyst One', email: 'analyst1@sentinelshield.demo', role: 'analyst', department: 'SOC Tier 2 Cyber Investigations' },
  { id: 'usr-analyst-2', name: 'Analyst Two', email: 'analyst2@sentinelshield.demo', role: 'analyst', department: 'SOC Tier 1 Investigations' },
  { id: 'usr-viewer-1', name: 'David Mercer', email: 'viewer@sentinelshield.io', role: 'viewer', department: 'Risk & Legal Compliance' },
];

export const DEFAULT_SOURCES: MonitoringSource[] = [
  { id: 'src-play', name: 'Google Play Store', type: 'app_store', platform: 'google_play', status: 'simulated', lastSync: '2026-10-08T11:15:00Z', recordsScanned: 14208, threatsDetected: 4, syncIntervalHours: 4 },
  { id: 'src-appstore', name: 'Apple App Store', type: 'app_store', platform: 'apple_app_store', status: 'simulated', lastSync: '2026-10-08T10:45:00Z', recordsScanned: 9840, threatsDetected: 1, syncIntervalHours: 6 },
  { id: 'src-x', name: 'X / Twitter Intelligence Feed', type: 'social', platform: 'x_twitter', status: 'simulated', lastSync: '2026-10-08T11:28:00Z', recordsScanned: 38200, threatsDetected: 6, syncIntervalHours: 1 },
  { id: 'src-instagram', name: 'Instagram Graph Monitor', type: 'social', platform: 'instagram', status: 'simulated', lastSync: '2026-10-08T09:12:00Z', recordsScanned: 18450, threatsDetected: 2, syncIntervalHours: 2 },
  { id: 'src-linkedin', name: 'LinkedIn Company Scraper', type: 'social', platform: 'linkedin', status: 'simulated', lastSync: '2026-10-08T08:30:00Z', recordsScanned: 7120, threatsDetected: 1, syncIntervalHours: 8 },
  { id: 'src-facebook', name: 'Facebook Pages Indexer', type: 'social', platform: 'facebook', status: 'simulated', lastSync: '2026-10-08T07:50:00Z', recordsScanned: 12400, threatsDetected: 1, syncIntervalHours: 4 },
  { id: 'src-youtube', name: 'YouTube Channel Scanner', type: 'social', platform: 'youtube', status: 'simulated', lastSync: '2026-10-08T06:00:00Z', recordsScanned: 5200, threatsDetected: 0, syncIntervalHours: 12 },
];

export const DEFAULT_WATCHLISTS: WatchlistRule[] = [
  { id: 'w-1', name: 'Crypto & Banking Phishing Lures', targetType: 'keyword', pattern: 'claim reward|verify your account|airdrop|urgent hotline|free bonus', severity: 'critical', enabled: true, hitsCount: 14, createdAt: '2026-02-01T10:00:00Z' },
  { id: 'w-2', name: 'Known Rogue Android Studios', targetType: 'publisher', pattern: 'Rogue Apps LLC|FastApps Studio|ShadowSoft APK', severity: 'critical', enabled: true, hitsCount: 8, createdAt: '2026-02-10T10:00:00Z' },
  { id: 'w-3', name: 'Domain Typosquat TLDs', targetType: 'domain', pattern: '.biz|.xyz|.top|.claims|.support-online.net', severity: 'high', enabled: true, hitsCount: 22, createdAt: '2026-03-01T10:00:00Z' },
];
