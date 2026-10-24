export const SCORING_WEIGHTS = {
  nameSimilarity: 25,
  publisherMismatch: 20,
  developerMismatch: 15,
  descriptionSimilarity: 15,
  logoSimilarity: 10,
  packageMismatch: 5,
  domainMismatch: 5,
  suspiciousLanguage: 5,
  accountVerification: 5,
  homoglyph: 15,
  recentCreation: 5,
  exactNameClone: 20,
  socialUsernameSimilarity: 25,
  socialDisplayNameSimilarity: 20,
  socialSuspiciousLanguage: 15,
  socialDomainMismatch: 15,
  verificationMismatch: 10,
} as const;

export const MAX_RISK_SCORE = 100;

export const SEVERITY_THRESHOLDS = {
  critical: 85,
  high: 75,
  medium: 50,
  low: 20,
} as const;

const runtime = globalThis as typeof globalThis & {
  process?: { env?: Record<string, string | undefined> };
};
export const HIGH_THRESHOLD = Number(
  runtime.process?.env?.HIGH_THRESHOLD || import.meta.env?.VITE_HIGH_THRESHOLD || 75,
);
export const LOGO_MATCH_THRESHOLD = Number(
  runtime.process?.env?.LOGO_MATCH_THRESHOLD || import.meta.env?.VITE_LOGO_MATCH_THRESHOLD || 80,
);

export function severityForScore(score: number): 'critical' | 'high' | 'medium' | 'low' | 'informational' {
  if (score >= SEVERITY_THRESHOLDS.critical) return 'critical';
  if (score >= SEVERITY_THRESHOLDS.high) return 'high';
  if (score >= SEVERITY_THRESHOLDS.medium) return 'medium';
  if (score >= SEVERITY_THRESHOLDS.low) return 'low';
  return 'informational';
}
