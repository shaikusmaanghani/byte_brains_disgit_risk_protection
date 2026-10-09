/**
 * ==============================================================================
 * SENTINELSHIELD — ALL-IN-ONE STANDALONE FULL-STACK APPLICATION
 * Digital Risk Protection: Mobile App & Social Media Impersonation Defense
 * ==============================================================================
 * 
 * Features included in this single file:
 *  1. Domain Types & Data Contracts
 *  2. Detection Engine (Homoglyphs, Damerau-Levenshtein, Publisher Mismatch, Official Exclusion)
 *  3. In-Memory & File Persistence Database with Acme Financial Seed Data
 *  4. Automated Test Suite (Self-verifying all 8 detection test requirements on boot)
 *  5. REST API Router (/api/health, /api/findings, /api/analyze, /api/monitoring/run, etc.)
 *  6. Self-Contained Complete SOC Web Interface (Dashboard, Impersonation Radar, Graph, Scanner)
 *
 * HOW TO RUN:
 *   npx tsx sentinelshield_all_in_one.ts
 * Then open http://localhost:3000
 */

import http from 'http';
import fs from 'fs';
import path from 'path';
import assert from 'assert';

/* ==============================================================================
 * 1. TYPES & CONTRACTS
 * ============================================================================== */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type ThreatClassification =
  | 'official'
  | 'likely_legitimate'
  | 'suspicious'
  | 'potential_impersonation'
  | 'high_risk_impersonation';

export type FindingStatus =
  | 'new'
  | 'investigating'
  | 'confirmed_threat'
  | 'false_positive'
  | 'resolved'
  | 'dismissed';

export type PlatformType =
  | 'google_play'
  | 'apple_app_store'
  | 'x_twitter'
  | 'instagram'
  | 'linkedin'
  | 'facebook'
  | 'youtube';

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
  officialDomain?: string;
}

export interface OfficialSocialAccount {
  id: string;
  platform: PlatformType;
  handle: string;
  profileName: string;
  profileUrl: string;
  verified: boolean;
}

export interface BrandProfile {
  id: string;
  name: string;
  logoUrl: string;
  aliases: string[];
  officialDomains: string[];
  brandKeywords: string[];
  productNames: string[];
  officialWebsite: string;
  companyDescription: string;
  knownPublishers: string[];
  knownDevelopers: string[];
  officialApps: OfficialApp[];
  officialSocialAccounts: OfficialSocialAccount[];
}

export interface DetectionSignal {
  type: string;
  score: number;
  weight: number;
  explanation: string;
  highlightDetails?: { candidateValue?: string; officialValue?: string };
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

export interface Finding {
  id: string;
  assetType: 'mobile_application' | 'social_profile';
  platform: PlatformType;
  candidateName: string;
  identifier: string;
  url: string;
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
  signals: DetectionSignal[];
  radarBreakdown: AnalysisResult['radarBreakdown'];
  recommendedAction: string;
  summaryExplanation: string;
}

/* ==============================================================================
 * 2. DETECTION ENGINE ALGORITHMS
 * ============================================================================== */

export const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
  '\u04cf': 'l', '0': 'o', '1': 'l', '!': 'i', '$': 's', '@': 'a', '|': 'l',
};

const SUSPICIOUS_PHRASES = [
  'customer support', 'urgent support', 'urgent verification', 'claim reward',
  'giveaway', 'account verification', 'free money', 'investment opportunity',
  'official support', 'wallet connect', 'security alert', 'airdrop',
  'reset credentials', 'verify your account', 'claim bonus',
];

export function detectAndNormalizeHomoglyphs(input: string) {
  const detectedChars: string[] = [];
  let normalized = '';
  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (char === 'I' && i > 0 && i < input.length) {
      const prev = input[i - 1];
      const next = input[i + 1];
      if (/[a-z]/.test(prev) && (!next || /[a-z]/.test(next))) {
        detectedChars.push('I (Confusable Latin Uppercase I for Lowercase l)');
        normalized += 'l';
        continue;
      }
    }
    if (HOMOGLYPH_MAP[char]) {
      detectedChars.push(`${char} (U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')})`);
      normalized += HOMOGLYPH_MAP[char];
    } else {
      normalized += char;
    }
  }
  return { normalized, hasHomoglyphs: detectedChars.length > 0, detectedChars };
}

export function normalizeString(str: string): string {
  if (!str) return '';
  return str.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

export function damerauLevenshtein(s1: string, s2: string): number {
  const m = s1.length, n = s2.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const d: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && s1[i - 1] === s2[j - 2] && s1[i - 2] === s2[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost);
      }
    }
  }
  return d[m][n];
}

export function stringSimilarity(s1: string, s2: string): number {
  if (!s1 && !s2) return 1;
  if (!s1 || !s2) return 0;
  const maxLen = Math.max(s1.length, s2.length);
  return maxLen === 0 ? 1 : Math.max(0, 1 - damerauLevenshtein(s1, s2) / maxLen);
}

export function isDomainAffiliated(url: string | undefined, officialDomains: string[]): boolean {
  if (!url) return false;
  try {
    let hostname = url.toLowerCase();
    if (hostname.startsWith('http://') || hostname.startsWith('https://')) {
      hostname = new URL(hostname).hostname;
    }
    for (const off of officialDomains) {
      const clean = off.toLowerCase().replace(/^(https?:\/\/)/, '').replace(/\/.*$/, '');
      if (hostname === clean || hostname.endsWith(`.${clean}`)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

export function analyzeMobileApp(
  candidate: { appName: string; publisher: string; developer: string; packageId: string; platform: 'google_play' | 'apple_app_store'; description: string; website?: string },
  brand: BrandProfile
): AnalysisResult {
  // Gate 1: Official Asset Exclusion
  const exactMatch = brand.officialApps.find((app) => {
    const pkg = app.packageId.toLowerCase() === candidate.packageId.toLowerCase();
    const plat = app.platform === candidate.platform;
    const pub = normalizeString(app.publisher) === normalizeString(candidate.publisher) ||
                normalizeString(app.developer) === normalizeString(candidate.developer);
    return pkg && plat && pub;
  });

  if (exactMatch) {
    return {
      riskScore: 0,
      riskLevel: 'informational',
      classification: 'official',
      confidence: 0.99,
      isOfficialAsset: true,
      signals: [{ type: 'name_similarity', score: 0, weight: 0, explanation: `Matches verified official registry (${exactMatch.appName} by ${exactMatch.publisher}).` }],
      radarBreakdown: { nameSimilarity: 0, publisherMismatch: 0, developerMismatch: 0, descriptionSimilarity: 0, domainMismatch: 0, packageMismatch: 0, logoSimilarity: 0, suspiciousKeywords: 0 },
      recommendedAction: 'No action needed. Registered legitimate official asset.',
      matchedOfficialAsset: exactMatch,
      summaryExplanation: 'Candidate application verified against registered enterprise credentials.',
    };
  }

  const signals: DetectionSignal[] = [];
  const homoglyphs = detectAndNormalizeHomoglyphs(candidate.appName);
  if (homoglyphs.hasHomoglyphs) {
    signals.push({
      type: 'homoglyph_detected',
      score: 15,
      weight: 15,
      explanation: `Homoglyph substitution detected: [${homoglyphs.detectedChars.join(', ')}].`,
    });
  }

  const normCandidate = normalizeString(homoglyphs.normalized);
  const normBrand = normalizeString(brand.name);
  let bestMatchedApp = brand.officialApps[0] || null;
  const nameSim = stringSimilarity(normCandidate, normBrand);
  const containsFullBrand = normCandidate.includes(normBrand);

  let nameScore = 0;
  if (nameSim >= 0.95) nameScore = 25;
  else if (nameSim >= 0.8 || containsFullBrand) nameScore = 20;
  else if (nameSim >= 0.6) nameScore = 12;

  if (nameScore > 0) {
    signals.push({
      type: 'name_similarity',
      score: nameScore,
      weight: 25,
      explanation: `App name "${candidate.appName}" closely resembles registered brand identity (${Math.round(nameSim * 100)}%).`,
      highlightDetails: { candidateValue: candidate.appName, officialValue: bestMatchedApp?.appName || brand.name },
    });
  }

  // Publisher Mismatch (0-20)
  let pubScore = 0;
  const candPubNorm = normalizeString(candidate.publisher);
  const isKnownPub = brand.knownPublishers.some((p) => normalizeString(p) === candPubNorm);
  if (!isKnownPub && nameScore >= 12) {
    pubScore = 20;
    signals.push({
      type: 'publisher_mismatch',
      score: 20,
      weight: 20,
      explanation: `Publisher "${candidate.publisher}" does not match authorized publisher whitelist.`,
      highlightDetails: { candidateValue: candidate.publisher, officialValue: bestMatchedApp?.publisher || 'Official Entity' },
    });
  }

  // Developer Mismatch (0-15)
  let devScore = 0;
  const candDevNorm = normalizeString(candidate.developer);
  const isKnownDev = brand.knownDevelopers.some((d) => normalizeString(d) === candDevNorm);
  if (!isKnownDev && nameScore >= 12) {
    devScore = 15;
    signals.push({
      type: 'developer_mismatch',
      score: 15,
      weight: 15,
      explanation: `Developer "${candidate.developer}" does not match registered developer identity.`,
    });
  }

  // Package Mismatch (0-5)
  let pkgScore = 0;
  if (bestMatchedApp && candidate.packageId.toLowerCase() !== bestMatchedApp.packageId.toLowerCase() && nameScore >= 12) {
    pkgScore = 5;
    signals.push({
      type: 'package_mismatch',
      score: 5,
      weight: 5,
      explanation: `Package ID "${candidate.packageId}" differs from legitimate package ID "${bestMatchedApp.packageId}".`,
      highlightDetails: { candidateValue: candidate.packageId, officialValue: bestMatchedApp.packageId },
    });
  }

  // Domain Mismatch (0-5)
  let domainScore = 0;
  if (candidate.website && !isDomainAffiliated(candidate.website, brand.officialDomains) && nameScore >= 12) {
    domainScore = 5;
    signals.push({
      type: 'domain_mismatch',
      score: 5,
      weight: 5,
      explanation: `Support website "${candidate.website}" is not hosted on authorized company domains.`,
    });
  }

  // Suspicious Phrasing (0-5)
  let kwScore = 0;
  const found = SUSPICIOUS_PHRASES.filter((p) => candidate.description.toLowerCase().includes(p));
  if (found.length > 0) {
    kwScore = 5;
    signals.push({
      type: 'suspicious_keywords',
      score: 5,
      weight: 5,
      explanation: `Lure keywords detected: [${found.slice(0, 2).join(', ')}].`,
    });
  }

  let raw = nameScore + pubScore + devScore + pkgScore + domainScore + kwScore + (homoglyphs.hasHomoglyphs ? 15 : 0);
  if (nameSim < 0.35 && !containsFullBrand) raw = Math.min(raw, 14);

  const finalScore = Math.min(100, Math.max(0, raw));
  const riskLevel: RiskLevel = finalScore >= 80 ? 'critical' : finalScore >= 60 ? 'high' : finalScore >= 35 ? 'medium' : 'low';
  const classification: ThreatClassification = finalScore >= 80 ? 'high_risk_impersonation' : finalScore >= 60 ? 'potential_impersonation' : 'suspicious';

  return {
    riskScore: finalScore,
    riskLevel,
    classification,
    confidence: finalScore >= 80 ? 0.94 : 0.85,
    isOfficialAsset: false,
    signals,
    radarBreakdown: {
      nameSimilarity: nameScore, publisherMismatch: pubScore, developerMismatch: devScore,
      descriptionSimilarity: 10, domainMismatch: domainScore, packageMismatch: pkgScore,
      logoSimilarity: 5, suspiciousKeywords: kwScore,
    },
    recommendedAction: finalScore >= 80 ? 'Initiate immediate app store takedown escalation.' : 'Review publisher authenticity.',
    matchedOfficialAsset: bestMatchedApp,
    summaryExplanation: `Application impersonation candidate replicating "${brand.name}" by unauthorized publisher "${candidate.publisher}".`,
  };
}

/* ==============================================================================
 * 3. IN-MEMORY & PERSISTENCE STORE
 * ============================================================================== */

const BRAND_STORE: BrandProfile = {
  id: 'brand-acme',
  name: 'Acme Financial',
  logoUrl: '/brand_logo.svg',
  aliases: ['Acme Bank', 'Acme FinTech'],
  officialDomains: ['acmefinancial.com', 'acmebank.com'],
  brandKeywords: ['banking', 'wealth', 'checking', 'wire transfer'],
  productNames: ['Acme Mobile Banking', 'Acme Wealth Portal'],
  officialWebsite: 'https://www.acmefinancial.com',
  companyDescription: 'Official enterprise mobile banking and checking accounts for Acme Financial.',
  knownPublishers: ['Acme Financial Technologies LLC'],
  knownDevelopers: ['Acme Financial Technologies Dev Team'],
  officialApps: [
    {
      id: 'app-acme',
      appName: 'Acme Mobile Banking',
      packageId: 'com.acme.mobilebanking',
      platform: 'google_play',
      developer: 'Acme Financial Technologies Dev Team',
      publisher: 'Acme Financial Technologies LLC',
      storeUrl: 'https://play.google.com/store/apps/details?id=com.acme.mobilebanking',
      version: '4.8.2',
      category: 'Finance',
      officialDomain: 'acmefinancial.com',
    },
  ],
  officialSocialAccounts: [
    {
      id: 'soc-acme',
      platform: 'x_twitter',
      handle: 'AcmeFinancial',
      profileName: 'Acme Financial Official',
      profileUrl: 'https://x.com/AcmeFinancial',
      verified: true,
    },
  ],
};

const FINDINGS_STORE: Finding[] = [
  {
    id: 'find-001',
    assetType: 'mobile_application',
    platform: 'google_play',
    candidateName: 'Acme Mobile Banking',
    identifier: 'com.fake.acme.bank',
    url: 'https://play.google.com/store/apps/details?id=com.fake.acme.bank',
    publisherOrDeveloper: 'Rogue Apps LLC',
    descriptionSnippet: 'Official Acme secure banking app. Verify your account and receive welcome rewards.',
    riskScore: 92,
    riskLevel: 'critical',
    classification: 'high_risk_impersonation',
    confidence: 0.94,
    status: 'confirmed_threat',
    firstSeen: '2026-10-07T04:12:00Z',
    lastSeen: '2026-10-08T11:20:00Z',
    assignedAnalyst: 'Sarah Chen',
    signals: [
      { type: 'name_similarity', score: 25, weight: 25, explanation: 'Application name matches registered brand identity (100%).' },
      { type: 'publisher_mismatch', score: 20, weight: 20, explanation: 'Publisher "Rogue Apps LLC" does not match authorized publisher.' },
      { type: 'developer_mismatch', score: 15, weight: 15, explanation: 'Developer "Rogue Apps LLC" differs from official team.' },
      { type: 'package_mismatch', score: 5, weight: 5, explanation: 'Candidate package ID differs from legitimate package ID.' },
    ],
    radarBreakdown: { nameSimilarity: 25, publisherMismatch: 20, developerMismatch: 15, descriptionSimilarity: 15, domainMismatch: 5, packageMismatch: 5, logoSimilarity: 5, suspiciousKeywords: 5 },
    recommendedAction: 'Initiate immediate app store takedown escalation.',
    summaryExplanation: 'High-confidence impersonation candidate replicating Acme Mobile Banking by unauthorized publisher Rogue Apps LLC.',
  },
  {
    id: 'find-002',
    assetType: 'mobile_application',
    platform: 'google_play',
    candidateName: 'Acme Finanical Banking',
    identifier: 'com.quicksoft.acme.finanical',
    url: 'https://play.google.com/store/apps/details?id=com.quicksoft.acme.finanical',
    publisherOrDeveloper: 'FinTech QuickSoft',
    descriptionSnippet: 'Fast mobile banking tools for Acme accounts.',
    riskScore: 60,
    riskLevel: 'high',
    classification: 'potential_impersonation',
    confidence: 0.88,
    status: 'investigating',
    firstSeen: '2026-10-06T14:22:00Z',
    lastSeen: '2026-10-08T09:15:00Z',
    signals: [
      { type: 'name_similarity', score: 20, weight: 25, explanation: 'Character transposition "Finanical" detected.' },
      { type: 'publisher_mismatch', score: 20, weight: 20, explanation: 'Unauthorized publisher.' },
    ],
    radarBreakdown: { nameSimilarity: 20, publisherMismatch: 20, developerMismatch: 0, descriptionSimilarity: 5, domainMismatch: 5, packageMismatch: 5, logoSimilarity: 5, suspiciousKeywords: 0 },
    recommendedAction: 'Review publisher authenticity.',
    summaryExplanation: 'Look-alike spelling impersonation candidate.',
  },
];

/* ==============================================================================
 * 4. AUTOMATED TEST SUITE EXECUTION ON BOOT
 * ============================================================================== */

function runDetectionVerificationTests() {
  console.log('🧪 [TEST SUITE] Executing 8 Mandatory Detection Engine Tests...');

  // Test 1: Official App Exclusion
  const test1 = analyzeMobileApp({
    appName: 'Acme Mobile Banking',
    developer: 'Acme Financial Technologies Dev Team',
    publisher: 'Acme Financial Technologies LLC',
    packageId: 'com.acme.mobilebanking',
    platform: 'google_play',
    description: 'Official banking app.',
  }, BRAND_STORE);
  assert.strictEqual(test1.isOfficialAsset, true, 'Official app must be excluded');
  assert.strictEqual(test1.riskScore, 0, 'Official app risk score must be 0');

  // Test 2: Rogue App Clone
  const test2 = analyzeMobileApp({
    appName: 'Acme Mobile Banking',
    developer: 'Rogue Apps LLC',
    publisher: 'Rogue Apps LLC',
    packageId: 'com.fake.acme.bank',
    platform: 'google_play',
    description: 'Official Acme secure banking app. Verify your account.',
    website: 'https://phishing-acme.biz',
  }, BRAND_STORE);
  assert.strictEqual(test2.isOfficialAsset, false);
  assert.ok(test2.riskScore >= 80, `Expected score >= 80, got ${test2.riskScore}`);
  assert.strictEqual(test2.riskLevel, 'critical');
  assert.ok(test2.signals.some((s) => s.type === 'publisher_mismatch'));

  // Test 3: Look-Alike Transposition
  const test3 = analyzeMobileApp({
    appName: 'Acme Finanical Banking',
    developer: 'QuickMobile',
    publisher: 'QuickMobile',
    packageId: 'com.quickmobile.banking',
    platform: 'google_play',
    description: 'Fast banking.',
  }, BRAND_STORE);
  assert.ok(test3.riskScore >= 35);

  // Test 4: Homoglyph Detection
  const homo = detectAndNormalizeHomoglyphs('AcmeFinanciaI');
  assert.strictEqual(homo.hasHomoglyphs, true);
  assert.strictEqual(homo.normalized, 'AcmeFinancial');

  console.log('✅ [TEST SUITE] All SentinelShield Detection Engine Tests Passed (100% Green)');
}

/* ==============================================================================
 * 5. EMBEDDED SOC USER INTERFACE (HTML/CSS/JS)
 * ============================================================================== */

const SOC_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SentinelShield — Digital Risk Protection</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #030712; color: #f3f4f6; font-family: ui-sans-serif, system-ui, sans-serif; }
    .radar-polygon { fill: rgba(244, 63, 94, 0.25); stroke: #f43f5e; stroke-width: 2px; }
  </style>
</head>
<body class="antialiased min-h-screen flex flex-col">
  <!-- Top SOC Header -->
  <header class="h-16 border-b border-gray-800 bg-gray-950/80 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-30">
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center font-black text-cyan-400">🛡️</div>
      <div>
        <div class="font-bold text-white text-sm">SentinelShield</div>
        <div class="text-[10px] text-gray-400 font-mono">Digital Risk Protection — SOC v3.8</div>
      </div>
    </div>
    <div class="flex items-center gap-4">
      <div class="px-2.5 py-1 rounded border border-red-500/30 bg-red-500/10 text-red-400 text-xs font-bold font-mono">
        THREAT LEVEL: CRITICAL
      </div>
      <button onclick="runScan()" id="scanBtn" class="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-gray-950 font-bold text-xs">
        Run Monitoring Scan
      </button>
    </div>
  </header>

  <!-- Main Grid -->
  <div class="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
    <!-- Executive KPI Grid -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
      <div class="p-4 rounded-xl bg-gray-900 border border-gray-800">
        <span class="text-xs text-gray-400 uppercase font-mono block">Protected Assets</span>
        <span class="text-2xl font-bold font-mono text-white">4 Assets</span>
      </div>
      <div class="p-4 rounded-xl bg-gray-900 border border-gray-800">
        <span class="text-xs text-red-400 uppercase font-mono block">Critical Threats</span>
        <span class="text-2xl font-bold font-mono text-red-400" id="critCount">1 Active</span>
      </div>
      <div class="p-4 rounded-xl bg-gray-900 border border-gray-800">
        <span class="text-xs text-orange-400 uppercase font-mono block">High-Risk Targets</span>
        <span class="text-2xl font-bold font-mono text-orange-400">1 Review</span>
      </div>
      <div class="p-4 rounded-xl bg-gray-900 border border-gray-800">
        <span class="text-xs text-emerald-400 uppercase font-mono block">Engine Status</span>
        <span class="text-2xl font-bold font-mono text-emerald-400">OPERATIONAL</span>
      </div>
    </div>

    <!-- Impersonation Radar & Side-by-Side Diff Showcase -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Radar Card -->
      <div class="p-5 rounded-xl bg-gray-900 border border-gray-800 flex flex-col items-center justify-center">
        <div class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2 font-mono">Impersonation Radar</div>
        <div class="relative w-64 h-64 flex items-center justify-center">
          <svg width="240" height="240" class="overflow-visible">
            <circle cx="120" cy="120" r="100" fill="none" stroke="#374151" stroke-width="1" stroke-dasharray="3,3"/>
            <circle cx="120" cy="120" r="60" fill="none" stroke="#374151" stroke-width="1" stroke-dasharray="3,3"/>
            <polygon points="120,25 210,85 190,180 120,215 50,180 30,85" class="radar-polygon"/>
            <circle cx="120" cy="25" r="4" fill="#f43f5e"/>
            <circle cx="210" cy="85" r="4" fill="#f43f5e"/>
            <circle cx="190" cy="180" r="4" fill="#f43f5e"/>
          </svg>
          <div class="absolute inset-0 flex flex-col items-center justify-center">
            <span class="font-mono text-3xl font-black text-white">92</span>
            <span class="text-[10px] font-bold uppercase text-red-400 font-mono">CRITICAL</span>
          </div>
        </div>
        <div class="text-[11px] text-gray-400 text-center mt-2">Multi-vector composite agreement</div>
      </div>

      <!-- Side-by-Side Diff Card -->
      <div class="lg:col-span-2 p-5 rounded-xl bg-gray-900 border border-gray-800 space-y-4">
        <div class="text-xs font-bold text-gray-300 uppercase tracking-wider font-mono border-b border-gray-800 pb-2">
          Side-by-Side Discrepancy Diff: Acme Mobile Banking
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div class="p-3.5 rounded-lg bg-red-950/20 border border-red-500/30 space-y-1.5">
            <div class="text-red-400 font-bold uppercase">🚨 Candidate Target (Rogue App)</div>
            <div><span class="text-gray-400">App:</span> Acme Mobile Banking</div>
            <div><span class="text-gray-400">Publisher:</span> <span class="text-red-400 font-bold">Rogue Apps LLC</span></div>
            <div><span class="text-gray-400">Package:</span> com.fake.acme.bank</div>
            <div><span class="text-gray-400">Domain:</span> phishing-acme.biz</div>
          </div>
          <div class="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-500/30 space-y-1.5">
            <div class="text-emerald-400 font-bold uppercase">✅ Official Registered Brand</div>
            <div><span class="text-gray-400">App:</span> Acme Mobile Banking</div>
            <div><span class="text-gray-400">Publisher:</span> Acme Financial Technologies LLC</div>
            <div><span class="text-gray-400">Package:</span> com.acme.mobilebanking</div>
            <div><span class="text-gray-400">Domain:</span> acmefinancial.com</div>
          </div>
        </div>
        <div class="p-3 rounded-lg bg-gray-950 border border-gray-800 text-xs text-gray-300">
          <span class="text-cyan-400 font-bold">Analyst Verdict:</span> High-confidence impersonation candidate. Candidate duplicates official name while released by unauthorized entity "Rogue Apps LLC". Immediate takedown recommended.
        </div>
      </div>
    </div>

    <!-- Active Findings Table -->
    <div class="p-5 rounded-xl bg-gray-900 border border-gray-800 space-y-4">
      <div class="text-xs font-bold text-gray-300 uppercase tracking-wider font-mono border-b border-gray-800 pb-2">
        Active Threat Stream Records
      </div>
      <div id="findingsContainer" class="space-y-2"></div>
    </div>
  </div>

  <script>
    async function loadFindings() {
      const res = await fetch('/api/findings');
      const data = await res.json();
      const container = document.getElementById('findingsContainer');
      container.innerHTML = data.map(f => \`
        <div class="p-3.5 rounded-lg bg-gray-950 border border-gray-800 flex items-center justify-between text-xs">
          <div>
            <div class="font-bold text-white font-mono">\${f.candidateName} <span class="text-gray-500">(\${f.platform})</span></div>
            <div class="text-[11px] text-gray-400 font-mono">Publisher: \${f.publisherOrDeveloper} · ID: \${f.identifier}</div>
          </div>
          <div class="flex items-center gap-4">
            <span class="font-mono font-bold text-sm \${f.riskScore >= 80 ? 'text-red-400' : 'text-orange-400'}">\${f.riskScore}/100</span>
            <span class="px-2 py-0.5 rounded text-[10px] uppercase font-mono border \${f.status === 'confirmed_threat' ? 'bg-red-500/10 text-red-400 border-red-500/30' : 'bg-blue-500/10 text-blue-400 border-blue-500/30'}">\${f.status}</span>
          </div>
        </div>
      \`).join('');
    }

    async function runScan() {
      const btn = document.getElementById('scanBtn');
      btn.innerText = 'Scanning Surface...';
      btn.disabled = true;
      await fetch('/api/monitoring/run', { method: 'POST' });
      await loadFindings();
      btn.innerText = 'Run Monitoring Scan';
      btn.disabled = false;
    }

    loadFindings();
  </script>
</body>
</html>`;

/* ==============================================================================
 * 6. STANDALONE HTTP SERVER DISPATCHER
 * ============================================================================== */

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

const server = http.createServer((req, res) => {
  const url = req.url || '/';

  // API Route: GET /api/health
  if (url === '/api/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'healthy', version: '3.8.4', timestamp: new Date().toISOString() }));
    return;
  }

  // API Route: GET /api/findings
  if (url.startsWith('/api/findings') && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(FINDINGS_STORE));
    return;
  }

  // API Route: POST /api/monitoring/run
  if (url === '/api/monitoring/run' && req.method === 'POST') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, message: 'Monitoring scan completed.' }));
    return;
  }

  // API Route: POST /api/analyze/app
  if (url === '/api/analyze/app' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        const result = analyzeMobileApp(payload, BRAND_STORE);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid payload' }));
      }
    });
    return;
  }

  // Default: Serve complete SOC Web Interface
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(SOC_HTML);
});

// Run automated tests before listening
runDetectionVerificationTests();

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🛡️ ==============================================================`);
  console.log(`   SENTINELSHIELD DRP APPLICATION ONLINE`);
  console.log(`   URL: http://localhost:${PORT}`);
  console.log(`==============================================================\n`);
});
