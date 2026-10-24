/**
 * SentinelShield Threat Detection Engine
 * 
 * Production-grade detection engine evaluating brand impersonation across
 * mobile applications and social profiles. Implements Unicode normalization,
 * homoglyph replacement, Damerau-Levenshtein distance, token Jaccard similarity,
 * publisher verification, package ID analysis, and weighted evidence-based scoring.
 */

import type {
  BrandProfile,
  AppCandidateInput,
  SocialCandidateInput,
  AnalysisResult,
  DetectionSignal,
  OfficialApp,
  OfficialSocialAccount,
  RiskLevel,
  ThreatClassification,
} from '../types/index.js';
import { LOGO_MATCH_THRESHOLD, MAX_RISK_SCORE, SCORING_WEIGHTS, SEVERITY_THRESHOLDS } from './scoringConfig.js';
// Homoglyphs mapping: Cyrillic / Greek / visual confusable characters to Latin base
export const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic small look-alikes
  '\u0430': 'a', // Cyrillic a
  '\u0435': 'e', // Cyrillic e
  '\u043e': 'o', // Cyrillic o
  '\u0440': 'p', // Cyrillic er
  '\u0441': 'c', // Cyrillic es
  '\u0443': 'y', // Cyrillic u
  '\u0445': 'x', // Cyrillic ha
  '\u0456': 'i', // Cyrillic i
  '\u04cf': 'l', // Cyrillic palochka
  '\u0458': 'j', // Cyrillic je
  '\u0455': 's', // Cyrillic dze
  // Greek look-alikes
  '\u03b1': 'a', // Greek alpha
  '\u03bf': 'o', // Greek omicron
  '\u03bd': 'v', // Greek nu
  '\u03c1': 'p', // Greek rho
  // Latin / Numbers / Symbols confusables
  '0': 'o',
  '1': 'l',
  '!': 'i',
  '$': 's',
  '@': 'a',
  '|': 'l',
};

// Suspicious phrase indicators commonly used by phishing and impersonation campaigns
const SUSPICIOUS_PHRASES = [
  'customer support',
  'urgent support',
  'urgent verification',
  'claim reward',
  'giveaway',
  'account verification',
  'free money',
  'investment opportunity',
  'official support',
  'wallet connect',
  'security alert',
  'airdrop',
  'reset credentials',
  'verify your account',
  'claim bonus',
  'earn daily',
  'official hotline',
  'whatsapp support',
  'telegram support',
  'exclusive access',
  'login',
  'log in',
  'sign in',
  'password reset',
  'enter password',
];

const SUSPICIOUS_PERMISSIONS = [
  'android.permission.READ_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.SEND_SMS',
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.BIND_ACCESSIBILITY_SERVICE',
  'android.permission.READ_CONTACTS',
  'android.permission.RECORD_AUDIO',
  'android.permission.ACCESS_BACKGROUND_LOCATION',
];

function evidenceWithContributions(signals: DetectionSignal[]): DetectionSignal[] {
  return signals.map((signal) => ({
    ...signal,
    signal: signal.signal || signal.type,
    pointsContributed: signal.pointsContributed ?? signal.score,
    reason: signal.reason || signal.explanation,
  }));
}

function logoReason(similarity: number, distance: number | null, comparison?: {
  pHashDistance: number;
  dHashDistance: number;
  colorHistogramSimilarity: number;
  method: string;
}): string {
  const percentage = Math.round(similarity * 100);
  if (comparison) {
    const description = percentage >= LOGO_MATCH_THRESHOLD
      ? `Logo is ${percentage}% visually similar to the official logo`
      : `Logo comparison measured ${percentage}% similarity, below the ${LOGO_MATCH_THRESHOLD}% match threshold`;
    return `${description} (pHash distance ${comparison.pHashDistance}, dHash distance ${comparison.dHashDistance}, color histogram ${comparison.colorHistogramSimilarity}% similar; measured by ${comparison.method}).`;
  }
  return `Candidate logo dHash differs from the registered official logo by ${distance} of 64 bits (${percentage}% similarity).`;
}

/**
 * Detects visually confusable Unicode characters and converts to normalized Latin
 */
export function detectAndNormalizeHomoglyphs(input: string): {
  normalized: string;
  hasHomoglyphs: boolean;
  detectedChars: string[];
} {
  const detectedChars: string[] = [];
  let normalized = '';

  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    // Check uppercase 'I' when appearing in place of lowercase 'l' (e.g. AcmeFinanciaI)
    if (char === 'I' && i > 0 && i < input.length) {
      const prevChar = input[i - 1];
      const nextChar = input[i + 1];
      // If surrounded by lowercase letters, it's virtually always a homoglyph substitute for 'l'
      if (/[a-z]/.test(prevChar) && (!nextChar || /[a-z]/.test(nextChar))) {
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

  return {
    normalized,
    hasHomoglyphs: detectedChars.length > 0,
    detectedChars,
  };
}

/**
 * Clean & normalize string for resilient comparison
 */
export function normalizeString(str: string): string {
  if (!str) return '';
  return str
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '') // remove diacritics
    .toLowerCase()
    .replace(/[^a-z0-9]/g, ''); // strip spaces, underscores, dashes, punctuation
}

/**
 * Tokenize string into meaningful words
 */
export function tokenize(str: string): string[] {
  if (!str) return [];
  return str
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((t) => t.length > 1);
}

/**
 * Damerau-Levenshtein distance (handles insertions, deletions, substitutions, and adjacent transpositions)
 */
export function damerauLevenshtein(s1: string, s2: string): number {
  const m = s1.length;
  const n = s2.length;
  if (m === 0) return n;
  if (n === 0) return m;

  const d: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1, // deletion
        d[i][j - 1] + 1, // insertion
        d[i - 1][j - 1] + cost // substitution
      );

      // Transposition
      if (i > 1 && j > 1 && s1[i - 1] === s2[j - 2] && s1[i - 2] === s2[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost);
      }
    }
  }

  return d[m][n];
}

/**
 * Normalized string similarity based on edit distance (0.0 to 1.0)
 */
export function stringSimilarity(s1: string, s2: string): number {
  if (!s1 && !s2) return 1;
  if (!s1 || !s2) return 0;
  const left = normalizeComparisonString(s1);
  const right = normalizeComparisonString(s2);
  if (left === right) return 1;
  const maxLen = Math.max(left.length, right.length);
  if (maxLen === 0) return 1;
  const editSimilarity = Math.max(0, 1 - damerauLevenshtein(left, right) / maxLen);
  const jaro = jaroWinklerSimilarity(left, right);
  return editSimilarity * 0.7 + jaro * 0.3;
}

function normalizeComparisonString(value: string): string {
  return detectAndNormalizeHomoglyphs(value)
    .normalized
    .toLowerCase()
    .replace(/rn/g, 'm')
    .replace(/(official|support|help|service)$/g, '')
    .replace(/[^a-z0-9]/g, '');
}

export function jaroWinklerSimilarity(left: string, right: string): number {
  if (left === right) return 1;
  if (!left || !right) return 0;
  const matchDistance = Math.max(Math.floor(Math.max(left.length, right.length) / 2) - 1, 0);
  const leftMatches = new Array(left.length).fill(false);
  const rightMatches = new Array(right.length).fill(false);
  let matches = 0;
  for (let i = 0; i < left.length; i++) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(i + matchDistance + 1, right.length);
    for (let j = start; j < end; j++) {
      if (rightMatches[j] || left[i] !== right[j]) continue;
      leftMatches[i] = true;
      rightMatches[j] = true;
      matches++;
      break;
    }
  }
  if (!matches) return 0;
  let transpositions = 0;
  let rightIndex = 0;
  for (let i = 0; i < left.length; i++) {
    if (!leftMatches[i]) continue;
    while (!rightMatches[rightIndex]) rightIndex++;
    if (left[i] !== right[rightIndex]) transpositions++;
    rightIndex++;
  }
  const jaro = (
    matches / left.length +
    matches / right.length +
    (matches - transpositions / 2) / matches
  ) / 3;
  let prefix = 0;
  while (prefix < Math.min(4, left.length, right.length) && left[prefix] === right[prefix]) prefix++;
  return jaro + prefix * 0.1 * (1 - jaro);
}

/**
 * Jaccard token similarity (0.0 to 1.0)
 */
export function tokenJaccardSimilarity(s1: string, s2: string): number {
  const t1 = new Set(tokenize(s1));
  const t2 = new Set(tokenize(s2));
  if (t1.size === 0 && t2.size === 0) return 1;
  if (t1.size === 0 || t2.size === 0) return 0;

  let intersection = 0;
  for (const token of t1) {
    if (t2.has(token)) intersection++;
  }

  const union = t1.size + t2.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/**
 * Token overlap ratio: percentage of query tokens contained in target
 */
export function tokenContainmentRatio(query: string, target: string): number {
  const qTokens = tokenize(query);
  const tTokens = new Set(tokenize(target));
  if (qTokens.length === 0) return 0;

  let matches = 0;
  for (const t of qTokens) {
    if (tTokens.has(t)) matches++;
  }
  return matches / qTokens.length;
}

/**
 * Compare two 64-bit difference hashes (dHashes) produced by image ingestion.
 */
export function computeLogoSimilarity(candidateHash?: string, officialHash?: string): number {
  const distance = perceptualHashDistance(candidateHash, officialHash);
  return distance === null ? 0 : 1 - distance / 64;
}

export function perceptualHashDistance(candidateHash?: string, officialHash?: string): number | null {
  if (!candidateHash || !officialHash || !/^[\da-f]{16}$/i.test(candidateHash) || !/^[\da-f]{16}$/i.test(officialHash)) {
    return null;
  }
  let differingBits = BigInt(`0x${candidateHash}`) ^ BigInt(`0x${officialHash}`);
  let distance = 0;
  while (differingBits) {
    distance += Number(differingBits & 1n);
    differingBits >>= 1n;
  }
  return distance;
}

function isRecentlyCreated(createdAt?: string): boolean {
  if (!createdAt) return false;
  const age = Date.now() - new Date(createdAt).getTime();
  return Number.isFinite(age) && age >= 0 && age <= 14 * 24 * 60 * 60 * 1000;
}

/**
 * Check if a candidate domain is affiliated with official domains
 */
export function isDomainAffiliated(urlOrDomain: string | undefined, officialDomains: string[]): boolean {
  if (!urlOrDomain) return false;
  try {
    let hostname = urlOrDomain;
    if (urlOrDomain.startsWith('http://') || urlOrDomain.startsWith('https://')) {
      hostname = new URL(urlOrDomain).hostname;
    }
    hostname = hostname.toLowerCase();

    for (const off of officialDomains) {
      const cleanOff = off.toLowerCase().replace(/^(https?:\/\/)/, '').replace(/\/.*$/, '');
      if (hostname === cleanOff || hostname.endsWith(`.${cleanOff}`)) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * ANALYZE MOBILE APPLICATION
 */
export function analyzeMobileApp(
  candidate: AppCandidateInput,
  brand: BrandProfile
): AnalysisResult {
  const signals: DetectionSignal[] = [];

  // Check 1: Official Asset Exclusion
  // Match criteria: exact platform AND exact packageId AND (publisher match OR developer match)
  const exactOfficialMatch = brand.officialApps.find((app) => {
    const pkgMatch = app.packageId.toLowerCase() === candidate.packageId.toLowerCase();
    const platMatch = app.platform === candidate.platform;
    const pubMatch =
      normalizeString(app.publisher) === normalizeString(candidate.publisher) ||
      normalizeString(app.developer) === normalizeString(candidate.developer);
    return pkgMatch && platMatch && pubMatch;
  });

  if (exactOfficialMatch) {
    return {
      riskScore: 0,
      riskLevel: 'informational',
      classification: 'official',
      confidence: 0.99,
      isOfficialAsset: true,
      signals: [
        {
          type: 'name_similarity',
          score: 0,
          weight: 0,
          explanation: `Application matches verified official registry (${exactOfficialMatch.appName} by ${exactOfficialMatch.publisher}).`,
        },
      ],
      radarBreakdown: {
        nameSimilarity: 0,
        publisherMismatch: 0,
        developerMismatch: 0,
        descriptionSimilarity: 0,
        domainMismatch: 0,
        packageMismatch: 0,
        logoSimilarity: 0,
        suspiciousKeywords: 0,
      },
      recommendedAction: 'No action needed. Registered as legitimate official enterprise asset.',
      matchedOfficialAsset: exactOfficialMatch,
      scoreBreakdown: {},
      summaryExplanation: 'Candidate application verified against registered enterprise official credentials.',
    };
  }

  // Find best matching official app for comparison
  let bestMatchedApp: OfficialApp | null = null;
  let highestAppSimilarity = 0;

  for (const offApp of brand.officialApps) {
    const normCand = normalizeString(candidate.appName);
    const normOff = normalizeString(offApp.appName);
    const sim = stringSimilarity(normCand, normOff);
    if (sim > highestAppSimilarity) {
      highestAppSimilarity = sim;
      bestMatchedApp = offApp;
    }
  }

  // Fallback to first official app if registered
  if (!bestMatchedApp && brand.officialApps.length > 0) {
    bestMatchedApp = brand.officialApps[0];
  }

  // Candidate homoglyph check
  const appNameHomoglyph = detectAndNormalizeHomoglyphs(candidate.appName);
  if (appNameHomoglyph.hasHomoglyphs) {
    signals.push({
      type: 'homoglyph_detected',
      score: SCORING_WEIGHTS.homoglyph,
      weight: SCORING_WEIGHTS.homoglyph,
      explanation: `Potential homoglyph substitution detected: [${appNameHomoglyph.detectedChars.join(', ')}]. Attacker may be attempting visual spoofing.`,
      highlightDetails: {
        candidateValue: candidate.appName,
        homoglyphsFound: appNameHomoglyph.detectedChars,
      },
    });
  }

  // Character transposition check (e.g. Acme Finanical vs Acme Financial)
  const normalizedCandidateName = normalizeString(appNameHomoglyph.normalized);
  const normalizedBrandName = normalizeString(brand.name);
  let bestNameSimilarity = stringSimilarity(normalizedCandidateName, normalizedBrandName);

  if (bestMatchedApp) {
    const appSim = stringSimilarity(
      normalizedCandidateName,
      normalizeString(bestMatchedApp.appName)
    );
    if (appSim > bestNameSimilarity) {
      bestNameSimilarity = appSim;
    }
  }

  // Check aliases and products
  for (const alias of [...brand.aliases, ...brand.productNames]) {
    const aliasSim = stringSimilarity(normalizedCandidateName, normalizeString(alias));
    if (aliasSim > bestNameSimilarity) {
      bestNameSimilarity = aliasSim;
    }
  }

  // Check if candidate name completely contains brand name or official app name (Added words pattern)
  const containsFullBrand =
    normalizedCandidateName.includes(normalizedBrandName) ||
    (bestMatchedApp && normalizedCandidateName.includes(normalizeString(bestMatchedApp.appName)));

  // Signal A: Name Similarity (0 - 25)
  let nameSimilarityScore = 0;
  let exactNameCloneScore = 0;
  if (bestNameSimilarity >= 0.95) {
    nameSimilarityScore = SCORING_WEIGHTS.nameSimilarity;
    signals.push({
      type: 'name_similarity',
      score: SCORING_WEIGHTS.nameSimilarity,
      weight: SCORING_WEIGHTS.nameSimilarity,
      explanation: `Application name "${candidate.appName}" matches registered brand identity with high fidelity (${Math.round(bestNameSimilarity * 100)}%).`,
      highlightDetails: {
        candidateValue: candidate.appName,
        officialValue: bestMatchedApp?.appName || brand.name,
      },
    });
  } else if (bestNameSimilarity >= 0.8 || containsFullBrand) {
    nameSimilarityScore = Math.round(SCORING_WEIGHTS.nameSimilarity * 0.8);
    const patternDesc = containsFullBrand
      ? `Application name "${candidate.appName}" embeds protected brand name with added words.`
      : `Application name "${candidate.appName}" is highly similar to registered brand identity (${Math.round(bestNameSimilarity * 100)}%).`;
    signals.push({
      type: 'name_similarity',
      score: Math.round(SCORING_WEIGHTS.nameSimilarity * 0.8),
      weight: SCORING_WEIGHTS.nameSimilarity,
      explanation: patternDesc,
      highlightDetails: {
        candidateValue: candidate.appName,
        officialValue: bestMatchedApp?.appName || brand.name,
      },
    });
  } else if (bestNameSimilarity >= 0.6) {
    nameSimilarityScore = Math.round(SCORING_WEIGHTS.nameSimilarity * 0.48);
    signals.push({
      type: 'name_similarity',
      score: Math.round(SCORING_WEIGHTS.nameSimilarity * 0.48),
      weight: SCORING_WEIGHTS.nameSimilarity,
      explanation: `Moderate brand name overlap detected (${Math.round(bestNameSimilarity * 100)}%).`,
    });
  } else if (bestNameSimilarity >= 0.4) {
    nameSimilarityScore = Math.round(SCORING_WEIGHTS.nameSimilarity * 0.2);
    signals.push({
      type: 'name_similarity',
      score: Math.round(SCORING_WEIGHTS.nameSimilarity * 0.2),
      weight: SCORING_WEIGHTS.nameSimilarity,
      explanation: `Low brand name resemblance (${Math.round(bestNameSimilarity * 100)}%).`,
    });
  }

  const normalizedOfficialAppName = normalizeComparisonString(bestMatchedApp?.appName || brand.name);
  const comparisonCandidateName = normalizeComparisonString(appNameHomoglyph.normalized);
  if (
    bestMatchedApp &&
    comparisonCandidateName === normalizedOfficialAppName &&
    !brand.knownPublishers.some((publisher) => normalizeString(publisher) === normalizeString(candidate.publisher))
  ) {
    exactNameCloneScore = SCORING_WEIGHTS.exactNameClone;
    signals.push({
      type: 'name_similarity',
      score: exactNameCloneScore,
      weight: exactNameCloneScore,
      explanation: 'The candidate uses the exact registered app name while naming an unrecognized publisher.',
      pointsContributed: exactNameCloneScore,
      signal: 'exact_name_clone',
      reason: 'Exact official app name paired with an unrecognized publisher.',
    });
  }

  // Signal B: Publisher Mismatch (0 - 20)
  let publisherMismatchScore = 0;
  const candidatePubNorm = normalizeString(candidate.publisher);
  const isKnownPublisher = brand.knownPublishers.some(
    (kp) => normalizeString(kp) === candidatePubNorm
  ) || (bestMatchedApp && normalizeString(bestMatchedApp.publisher) === candidatePubNorm);

  if (!isKnownPublisher && nameSimilarityScore >= 12) {
    publisherMismatchScore = SCORING_WEIGHTS.publisherMismatch;
    signals.push({
      type: 'publisher_mismatch',
      score: SCORING_WEIGHTS.publisherMismatch,
      weight: SCORING_WEIGHTS.publisherMismatch,
      explanation: `Publisher "${candidate.publisher}" does not match registered official publisher "${bestMatchedApp?.publisher || brand.knownPublishers.join(', ')}".`,
      highlightDetails: {
        candidateValue: candidate.publisher,
        officialValue: bestMatchedApp?.publisher || 'Official Brand Entity',
      },
    });
  } else if (!isKnownPublisher && nameSimilarityScore >= 5) {
    publisherMismatchScore = Math.round(SCORING_WEIGHTS.publisherMismatch * 0.5);
    signals.push({
      type: 'publisher_mismatch',
      score: Math.round(SCORING_WEIGHTS.publisherMismatch * 0.5),
      weight: SCORING_WEIGHTS.publisherMismatch,
      explanation: `Publisher "${candidate.publisher}" is not in the organization's verified publisher whitelist.`,
    });
  }

  // Signal C: Developer Mismatch (0 - 15)
  let developerMismatchScore = 0;
  const candidateDevNorm = normalizeString(candidate.developer);
  const isKnownDeveloper = brand.knownDevelopers.some(
    (kd) => normalizeString(kd) === candidateDevNorm
  ) || (bestMatchedApp && normalizeString(bestMatchedApp.developer) === candidateDevNorm);

  if (!isKnownDeveloper && candidateDevNorm !== candidatePubNorm && nameSimilarityScore >= 12) {
    developerMismatchScore = SCORING_WEIGHTS.developerMismatch;
    signals.push({
      type: 'developer_mismatch',
      score: SCORING_WEIGHTS.developerMismatch,
      weight: SCORING_WEIGHTS.developerMismatch,
      explanation: `Developer "${candidate.developer}" does not match the official developer on record.`,
      highlightDetails: {
        candidateValue: candidate.developer,
        officialValue: bestMatchedApp?.developer || 'Official Engineering Team',
      },
    });
  } else if (!isKnownDeveloper && candidateDevNorm !== candidatePubNorm && nameSimilarityScore >= 5) {
    developerMismatchScore = Math.round(SCORING_WEIGHTS.developerMismatch * 0.53);
  }

  // Signal D: Description Similarity & Brand Phrasing (0 - 15)
  let descriptionSimilarityScore = 0;
  const descTokens = tokenize(candidate.description);
  const officialDesc = bestMatchedApp ? bestMatchedApp.appName + ' ' + brand.companyDescription : brand.companyDescription;
  const jaccardDesc = tokenJaccardSimilarity(candidate.description, officialDesc);
  const brandKeywordsContained = brand.brandKeywords.filter((kw) =>
    candidate.description.toLowerCase().includes(kw.toLowerCase())
  );

  if (jaccardDesc >= 0.5 || brandKeywordsContained.length >= 3) {
    descriptionSimilarityScore = SCORING_WEIGHTS.descriptionSimilarity;
    signals.push({
      type: 'description_similarity',
      score: SCORING_WEIGHTS.descriptionSimilarity,
      weight: SCORING_WEIGHTS.descriptionSimilarity,
      explanation: `Description heavily replicates brand proprietary phrasing and keywords: [${brandKeywordsContained.join(', ')}].`,
      evidenceSnippet: candidate.description.slice(0, 140) + '...',
    });
  } else if (jaccardDesc >= 0.25 || brandKeywordsContained.length >= 1) {
    descriptionSimilarityScore = Math.round(SCORING_WEIGHTS.descriptionSimilarity * 0.53);
    signals.push({
      type: 'description_similarity',
      score: Math.round(SCORING_WEIGHTS.descriptionSimilarity * 0.53),
      weight: SCORING_WEIGHTS.descriptionSimilarity,
      explanation: `Candidate description references official brand terminology (${brandKeywordsContained.join(', ')}).`,
    });
  }

  // Signal E: Logo / Icon Similarity (0 - 10)
  let logoSimilarityScore = 0;
  const officialLogoHash = bestMatchedApp?.logoHash || brand.logoHash;
  const logoDistance = perceptualHashDistance(candidate.logoHash, officialLogoHash);
  const logoSim = candidate.logoComparison
    ? Math.max(0, Math.min(100, candidate.logoComparison.similarity)) / 100
    : computeLogoSimilarity(candidate.logoHash, officialLogoHash);
  if (logoSim > 0 || candidate.logoComparison) {
    logoSimilarityScore = Math.round(SCORING_WEIGHTS.logoSimilarity * logoSim);
    signals.push({
      type: 'logo_similarity',
      score: logoSimilarityScore,
      weight: SCORING_WEIGHTS.logoSimilarity,
      explanation: logoReason(logoSim, logoDistance, candidate.logoComparison),
    });
  }

  // Signal F: Package ID Mismatch (0 - 5)
  let packageMismatchScore = 0;
  if (bestMatchedApp) {
    const pkgMatch = candidate.packageId.toLowerCase() === bestMatchedApp.packageId.toLowerCase();
    if (!pkgMatch && nameSimilarityScore >= 12) {
      packageMismatchScore = SCORING_WEIGHTS.packageMismatch;
      signals.push({
        type: 'package_mismatch',
        score: SCORING_WEIGHTS.packageMismatch,
        weight: SCORING_WEIGHTS.packageMismatch,
        explanation: `Candidate bundle/package ID "${candidate.packageId}" differs from legitimate package ID "${bestMatchedApp.packageId}".`,
        highlightDetails: {
          candidateValue: candidate.packageId,
          officialValue: bestMatchedApp.packageId,
        },
      });
    }
  }

  // Signal G: Official Domain Mismatch (0 - 5)
  let domainMismatchScore = 0;
  if (candidate.website) {
    const isAffiliated = isDomainAffiliated(candidate.website, brand.officialDomains);
    if (!isAffiliated && nameSimilarityScore >= 12) {
      domainMismatchScore = SCORING_WEIGHTS.domainMismatch;
      signals.push({
        type: 'domain_mismatch',
        score: SCORING_WEIGHTS.domainMismatch,
        weight: SCORING_WEIGHTS.domainMismatch,
        explanation: `Support website "${candidate.website}" is not hosted on any authorized company domain (${brand.officialDomains.join(', ')}).`,
        highlightDetails: {
          candidateValue: candidate.website,
          officialValue: brand.officialDomains[0],
        },
      });
    }
  }

  // Signal H: Suspicious Phrasing & Permissions (0 - 5)
  let suspiciousKeywordsScore = 0;
  const foundPhrases = SUSPICIOUS_PHRASES.filter((p) =>
    candidate.description.toLowerCase().includes(p)
  );

  const foundSuspiciousPerms = (candidate.permissions || []).filter((p) =>
    SUSPICIOUS_PERMISSIONS.includes(p)
  );

  if (foundPhrases.length > 0 || foundSuspiciousPerms.length > 0) {
    suspiciousKeywordsScore = SCORING_WEIGHTS.suspiciousLanguage;
    const reasons: string[] = [];
    if (foundPhrases.length > 0) reasons.push(`High-risk phrases: [${foundPhrases.slice(0, 3).join(', ')}]`);
    if (foundSuspiciousPerms.length > 0) reasons.push(`Sensitive permissions: [${foundSuspiciousPerms.slice(0, 2).join(', ')}]`);
    signals.push({
      type: 'suspicious_keywords',
      score: SCORING_WEIGHTS.suspiciousLanguage,
      weight: SCORING_WEIGHTS.suspiciousLanguage,
      explanation: reasons.join('; '),
    });
  }
  const accountVerificationScore = /\b(account verification|verify your account|login to|log in to|sign in to)\b/i.test(candidate.description)
    ? SCORING_WEIGHTS.accountVerification
    : 0;
  if (accountVerificationScore) {
    signals.push({
      type: 'suspicious_keywords',
      score: accountVerificationScore,
      weight: SCORING_WEIGHTS.accountVerification,
      explanation: 'Description asks users to log in or verify an account.',
    });
  }

  if (logoDistance === null && !candidate.logoComparison) {
    signals.push({
      type: 'logo_comparison_skipped',
      score: 0,
      weight: SCORING_WEIGHTS.logoSimilarity,
      explanation: candidate.logoUnavailableReason || 'Logo not available; comparison skipped because a candidate or official logo image is unavailable.',
    });
  }

  const recentCreationScore = isRecentlyCreated(candidate.createdAt) ? SCORING_WEIGHTS.recentCreation : 0;
  if (recentCreationScore) {
    signals.push({
      type: 'recent_creation',
      score: recentCreationScore,
      weight: SCORING_WEIGHTS.recentCreation,
      explanation: 'Candidate creation date is within the last 14 days.',
    });
  }

  // Calculate Total Risk Score (Max 100)
  // If name similarity is negligible (< 0.2) and no brand keywords are found, do not flag unrelated apps!
  let rawScore =
    nameSimilarityScore +
    publisherMismatchScore +
    developerMismatchScore +
    descriptionSimilarityScore +
    logoSimilarityScore +
    packageMismatchScore +
    domainMismatchScore +
    suspiciousKeywordsScore +
    accountVerificationScore +
    recentCreationScore +
    exactNameCloneScore;

  // Add homoglyph weight if detected
  if (appNameHomoglyph.hasHomoglyphs) {
    rawScore = Math.min(MAX_RISK_SCORE, rawScore + SCORING_WEIGHTS.homoglyph);
  }

  // Critical safeguard: If name similarity is 0 and no brand tokens exist, cap score to prevent false positives
  if (bestNameSimilarity < 0.35 && brandKeywordsContained.length === 0) {
    rawScore = Math.min(rawScore, 14);
  }

  const finalScore = Math.min(MAX_RISK_SCORE, Math.max(0, rawScore));

  // Determine Risk Level & Classification
  let riskLevel: RiskLevel = 'informational';
  let classification: ThreatClassification = 'likely_legitimate';
  let recommendedAction = 'Continue routine monitoring.';
  let confidence = 0.75;

  if (finalScore >= SEVERITY_THRESHOLDS.critical) {
    riskLevel = 'critical';
    classification = 'high_risk_impersonation';
    confidence = 0.94;
    recommendedAction = 'Initiate immediate app store takedown escalation and publish consumer security advisory.';
  } else if (finalScore >= SEVERITY_THRESHOLDS.high) {
    riskLevel = 'high';
    classification = 'potential_impersonation';
    confidence = 0.88;
    recommendedAction = 'Review publisher authenticity, inspect APK/IPA binary permissions, and verify developer ownership.';
  } else if (finalScore >= SEVERITY_THRESHOLDS.medium) {
    riskLevel = 'medium';
    classification = 'suspicious';
    confidence = 0.80;
    recommendedAction = 'Assign analyst to verify relationship and monitor version updates.';
  } else if (finalScore >= SEVERITY_THRESHOLDS.low) {
    riskLevel = 'low';
    classification = 'likely_legitimate';
    confidence = 0.72;
    recommendedAction = 'Keep on passive watchlist; no active brand harm identified.';
  }

  const summaryExplanation =
    finalScore >= SEVERITY_THRESHOLDS.critical
      ? `High-confidence impersonation candidate. Replicates "${bestMatchedApp?.appName || brand.name}" while published by unauthorized entity "${candidate.publisher}".`
      : finalScore >= SEVERITY_THRESHOLDS.high
      ? `Potential unauthorized derivative or publisher mismatch masquerading as ${brand.name}.`
      : finalScore >= SEVERITY_THRESHOLDS.medium
      ? `Suspicious application bearing partial brand naming cues.`
      : `Application demonstrates low correlation with protected assets.`;

  return {
    riskScore: finalScore,
    riskLevel,
    classification,
    confidence,
    isOfficialAsset: false,
    signals: evidenceWithContributions(signals),
    radarBreakdown: {
      nameSimilarity: nameSimilarityScore,
      publisherMismatch: publisherMismatchScore,
      developerMismatch: developerMismatchScore,
      descriptionSimilarity: descriptionSimilarityScore,
      domainMismatch: domainMismatchScore,
      packageMismatch: packageMismatchScore,
      logoSimilarity: logoSimilarityScore,
      suspiciousKeywords: suspiciousKeywordsScore,
    },
    recommendedAction,
    matchedOfficialAsset: bestMatchedApp,
    summaryExplanation,
    scoreBreakdown: signals.reduce<Record<string, number>>((result, signal) => {
      result[signal.type] = (result[signal.type] || 0) + signal.score;
      return result;
    }, {}),
  };
}

/**
 * ANALYZE SOCIAL MEDIA CANDIDATE
 */
export function analyzeSocialCandidate(
  candidate: SocialCandidateInput,
  brand: BrandProfile
): AnalysisResult {
  const cleanHandle = candidate.username.replace(/^@/, '').toLowerCase();

  // Check 1: Official Handle Match
  const exactOfficialHandle = brand.officialSocialAccounts.find((acc) => {
    const accHandle = acc.handle.replace(/^@/, '').toLowerCase();
    return acc.platform === candidate.platform && accHandle === cleanHandle;
  });

  if (exactOfficialHandle) {
    return {
      riskScore: 0,
      riskLevel: 'informational',
      classification: 'official',
      confidence: 0.99,
      isOfficialAsset: true,
      signals: [
        {
          type: 'username_similarity',
          score: 0,
          weight: 0,
          explanation: `Matches verified official account registry (@${exactOfficialHandle.handle} on ${exactOfficialHandle.platform}).`,
        },
      ],
      radarBreakdown: {
        nameSimilarity: 0,
        publisherMismatch: 0,
        developerMismatch: 0,
        descriptionSimilarity: 0,
        domainMismatch: 0,
        packageMismatch: 0,
        logoSimilarity: 0,
        suspiciousKeywords: 0,
      },
      recommendedAction: 'No action needed. Registered as legitimate official enterprise social handle.',
      matchedOfficialAsset: exactOfficialHandle,
      summaryExplanation: 'Candidate profile verified against official enterprise social handles.',
    };
  }

  const signals: DetectionSignal[] = [];

  // Match against official accounts on the same platform if any
  const officialOnPlatform = brand.officialSocialAccounts.find(
    (acc) => acc.platform === candidate.platform
  ) || brand.officialSocialAccounts[0];

  // Homoglyphs in username or profile name
  const handleHomoglyphs = detectAndNormalizeHomoglyphs(candidate.username);
  const nameHomoglyphs = detectAndNormalizeHomoglyphs(candidate.profileName);

  if (handleHomoglyphs.hasHomoglyphs || nameHomoglyphs.hasHomoglyphs) {
    const allFound = [...handleHomoglyphs.detectedChars, ...nameHomoglyphs.detectedChars];
    signals.push({
      type: 'homoglyph_detected',
      score: SCORING_WEIGHTS.homoglyph,
      weight: SCORING_WEIGHTS.homoglyph,
      explanation: `Homoglyph character substitution detected: [${allFound.join(', ')}]. Highly characteristic of typo-squatting or visual spoofing.`,
      highlightDetails: {
        candidateValue: candidate.username,
        homoglyphsFound: allFound,
      },
    });
  }

  // Handle & Name Analysis
  const normHandle = normalizeString(handleHomoglyphs.normalized);
  const normBrand = normalizeString(brand.name);
  const officialHandleClean = officialOnPlatform ? normalizeString(officialOnPlatform.handle) : normBrand;

  const handleSim = stringSimilarity(normHandle, officialHandleClean);
  const brandInHandle = normHandle.includes(normBrand);

  let usernameSimilarityScore = 0;
  if (handleSim >= 0.9) {
    usernameSimilarityScore = SCORING_WEIGHTS.socialUsernameSimilarity;
    signals.push({
      type: 'username_similarity',
      score: SCORING_WEIGHTS.socialUsernameSimilarity,
      weight: SCORING_WEIGHTS.socialUsernameSimilarity,
      explanation: `Username @${candidate.username} is nearly indistinguishable from official brand identifier (@${officialOnPlatform?.handle || brand.name}).`,
      highlightDetails: {
        candidateValue: candidate.username,
        officialValue: officialOnPlatform?.handle || brand.name,
      },
    });
  } else if (brandInHandle) {
    usernameSimilarityScore = Math.round(SCORING_WEIGHTS.socialUsernameSimilarity * 0.8);
    signals.push({
      type: 'username_similarity',
      score: Math.round(SCORING_WEIGHTS.socialUsernameSimilarity * 0.8),
      weight: SCORING_WEIGHTS.socialUsernameSimilarity,
      explanation: `Username contains core brand token "${brand.name}" combined with modifier terms (e.g., support/help/official).`,
      highlightDetails: {
        candidateValue: candidate.username,
        officialValue: brand.name,
      },
    });
  } else if (handleSim >= 0.6) {
    usernameSimilarityScore = Math.round(SCORING_WEIGHTS.socialUsernameSimilarity * 0.4);
  }

  // Display Name Similarity
  let nameSimScore = 0;
  const normCandidateDisplayName = normalizeString(nameHomoglyphs.normalized);
  const displayNameSim = stringSimilarity(
    normCandidateDisplayName,
    normBrand
  );
  const displayNameContainsBrand = normCandidateDisplayName.includes(normBrand);

  if (displayNameSim >= 0.85 || displayNameContainsBrand) {
    nameSimScore = SCORING_WEIGHTS.socialDisplayNameSimilarity;
    signals.push({
      type: 'name_similarity',
      score: SCORING_WEIGHTS.socialDisplayNameSimilarity,
      weight: SCORING_WEIGHTS.socialDisplayNameSimilarity,
      explanation: `Profile display name "${candidate.profileName}" mimics protected brand name "${brand.name}".`,
    });
  } else if (displayNameSim >= 0.6) {
    nameSimScore = Math.round(SCORING_WEIGHTS.socialDisplayNameSimilarity * 0.5);
  }

  // Bio / Suspicious Phrasing
  let suspiciousKeywordsScore = 0;
  const bioPhrases = SUSPICIOUS_PHRASES.filter((p) =>
    candidate.biography.toLowerCase().includes(p)
  );

  if (bioPhrases.length > 0) {
    suspiciousKeywordsScore = SCORING_WEIGHTS.socialSuspiciousLanguage;
    signals.push({
      type: 'suspicious_keywords',
      score: SCORING_WEIGHTS.socialSuspiciousLanguage,
      weight: SCORING_WEIGHTS.socialSuspiciousLanguage,
      explanation: `Biography incorporates high-risk social engineering lures: [${bioPhrases.join(', ')}].`,
      evidenceSnippet: candidate.biography,
    });
  }

  // External Links Verification
  let domainMismatchScore = 0;
  if (candidate.links && candidate.links.length > 0) {
    const unverifiedLinks = candidate.links.filter(
      (link) => !isDomainAffiliated(link, brand.officialDomains)
    );
    if (unverifiedLinks.length > 0 && (brandInHandle || nameSimScore >= 10)) {
      domainMismatchScore = SCORING_WEIGHTS.socialDomainMismatch;
      signals.push({
        type: 'domain_mismatch',
        score: SCORING_WEIGHTS.socialDomainMismatch,
        weight: SCORING_WEIGHTS.socialDomainMismatch,
        explanation: `External bio links point to unauthorized third-party destinations (${unverifiedLinks.slice(0, 2).join(', ')}).`,
        highlightDetails: {
          candidateValue: unverifiedLinks[0],
          officialValue: brand.officialDomains[0],
        },
      });
    }
  }

  // Verification Mismatch (if official account is verified but candidate is not)
  let verificationScore = 0;
  if (officialOnPlatform?.verified && !candidate.verified && (brandInHandle || nameSimScore >= 10)) {
    verificationScore = SCORING_WEIGHTS.verificationMismatch;
    signals.push({
      type: 'verification_mismatch',
      score: SCORING_WEIGHTS.verificationMismatch,
      weight: SCORING_WEIGHTS.verificationMismatch,
      explanation: `Official handle @${officialOnPlatform.handle} holds verified status, while candidate profile lacks verification badge.`,
    });
  }

  // Logo similarity
  let logoScore = 0;
  const officialSocialLogoHash = officialOnPlatform?.avatarHash || brand.logoHash;
  const socialLogoDistance = perceptualHashDistance(candidate.avatarHash, officialSocialLogoHash);
  const socialLogoSimilarity = candidate.logoComparison
    ? Math.max(0, Math.min(100, candidate.logoComparison.similarity)) / 100
    : computeLogoSimilarity(candidate.avatarHash, officialSocialLogoHash);
  if (socialLogoSimilarity > 0 || candidate.logoComparison) {
    logoScore = Math.round(SCORING_WEIGHTS.logoSimilarity * socialLogoSimilarity);
    signals.push({
      type: 'logo_similarity',
      score: logoScore,
      weight: SCORING_WEIGHTS.logoSimilarity,
      explanation: logoReason(socialLogoSimilarity, socialLogoDistance, candidate.logoComparison),
    });
  }

  if (socialLogoDistance === null && !candidate.logoComparison) {
    signals.push({
      type: 'logo_comparison_skipped',
      score: 0,
      weight: SCORING_WEIGHTS.logoSimilarity,
      explanation: candidate.logoUnavailableReason || 'Logo not available; comparison skipped because a candidate or official logo image is unavailable.',
    });
  }

  const recentCreationScore = isRecentlyCreated(candidate.createdAt) ? SCORING_WEIGHTS.recentCreation : 0;
  if (recentCreationScore) {
    signals.push({
      type: 'recent_creation',
      score: recentCreationScore,
      weight: SCORING_WEIGHTS.recentCreation,
      explanation: 'Candidate creation date is within the last 14 days.',
    });
  }

  let totalScore =
    usernameSimilarityScore +
    nameSimScore +
    suspiciousKeywordsScore +
    domainMismatchScore +
    verificationScore +
    logoScore +
    recentCreationScore;

  if (handleHomoglyphs.hasHomoglyphs || nameHomoglyphs.hasHomoglyphs) {
    totalScore = Math.min(MAX_RISK_SCORE, totalScore + SCORING_WEIGHTS.homoglyph);
  }

  // If no handle or name relation, cap score
  if (!brandInHandle && displayNameSim < 0.4) {
    totalScore = Math.min(totalScore, 10);
  }

  const finalScore = Math.min(MAX_RISK_SCORE, Math.max(0, totalScore));

  let riskLevel: RiskLevel = 'informational';
  let classification: ThreatClassification = 'likely_legitimate';
  let recommendedAction = 'Routine passive observation.';
  let confidence = 0.75;

  if (finalScore >= SEVERITY_THRESHOLDS.critical) {
    riskLevel = 'critical';
    classification = 'high_risk_impersonation';
    confidence = 0.95;
    recommendedAction = 'Execute fast-track brand impersonation DMCA / Terms of Service takedown notice via platform API.';
  } else if (finalScore >= SEVERITY_THRESHOLDS.high) {
    riskLevel = 'high';
    classification = 'potential_impersonation';
    confidence = 0.88;
    recommendedAction = 'Issue platform report for deceptive impersonation and monitor direct messaging activities.';
  } else if (finalScore >= SEVERITY_THRESHOLDS.medium) {
    riskLevel = 'medium';
    classification = 'suspicious';
    confidence = 0.79;
    recommendedAction = 'Add account to high-frequency watchlist; track handle and bio modifications.';
  } else if (finalScore >= SEVERITY_THRESHOLDS.low) {
    riskLevel = 'low';
    classification = 'likely_legitimate';
    confidence = 0.70;
  }

  const summaryExplanation =
    finalScore >= SEVERITY_THRESHOLDS.critical
      ? `High-risk social profile spoofing @${officialOnPlatform?.handle || brand.name} using brand imagery, lures, and unauthorized web links.`
      : finalScore >= SEVERITY_THRESHOLDS.high
      ? `Potential unauthorized brand representative profile targeting ${brand.name} customers.`
      : finalScore >= SEVERITY_THRESHOLDS.medium
      ? `Account shares keywords with ${brand.name} but lacks definitive proof of malicious intent.`
      : `Profile shows incidental keyword overlap with registered brand.`;

  return {
    riskScore: finalScore,
    riskLevel,
    classification,
    confidence,
    isOfficialAsset: false,
    signals: evidenceWithContributions(signals),
    radarBreakdown: {
      nameSimilarity: nameSimScore,
      publisherMismatch: 0,
      developerMismatch: 0,
      descriptionSimilarity: suspiciousKeywordsScore,
      domainMismatch: domainMismatchScore,
      packageMismatch: 0,
      logoSimilarity: logoScore,
      suspiciousKeywords: suspiciousKeywordsScore,
    },
    recommendedAction,
    matchedOfficialAsset: officialOnPlatform,
    summaryExplanation,
    scoreBreakdown: signals.reduce<Record<string, number>>((result, signal) => {
      result[signal.type] = (result[signal.type] || 0) + signal.score;
      return result;
    }, {}),
  };
}
