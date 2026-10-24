import type { Finding } from '../types/index.js';

const UNSUPPORTED_CLAIMS = /\b(fraud|fraudulent|criminal|intent|intended|damage|damaged|maliciously)\b/i;

export function draftTakedownReport(finding: Finding, actor: string): string {
  if ((finding.investigationStatus || '') !== 'Confirmed' && finding.status !== 'confirmed_threat') {
    throw new Error('Takedown reports are available only for Confirmed detections.');
  }
  const evidence = (finding.signals || [])
    .filter((signal) => signal.score > 0)
    .map((signal) => `- ${signal.type.replace(/_/g, ' ')}: ${signal.score} points (weight ${signal.weight}). ${signal.explanation}`)
    .join('\n') || '- No positive scoring evidence was recorded.';
  const hasLogoEvidence = (finding.signals || []).some((signal) => signal.type === 'logo_similarity' && signal.score > 0);
  const logoThreshold = finding.logoMatchThreshold || 80;
  const logoEvidence = finding.logoComparison && !hasLogoEvidence
    ? `- Logo similarity: 0 points. ${finding.logoComparison.similarity >= logoThreshold
      ? `The candidate logo appears visually similar at ${finding.logoComparison.similarity}%`
      : `Observed logo similarity was ${finding.logoComparison.similarity}%, below the ${logoThreshold}% match threshold`}; pHash distance ${finding.logoComparison.pHashDistance}, dHash distance ${finding.logoComparison.dHashDistance}, color histogram similarity ${finding.logoComparison.colorHistogramSimilarity}%, method ${finding.logoComparison.method}.`
    : '';
  const foundSignals = new Set((finding.signals || []).filter((signal) => signal.score > 0).map((signal) => signal.type));
  const expectedSignals = ['name_similarity', 'description_similarity', 'publisher_mismatch', 'domain_mismatch', 'logo_similarity'];
  const notFound = expectedSignals
    .filter((signal) => !foundSignals.has(signal as typeof finding.signals[number]['type']))
    .map((signal) => signal.replace(/_/g, ' '));
  const official = finding.matchedOfficialAsset;
  const officialName = official && 'appName' in official
    ? official.appName
    : official && 'profileName' in official
      ? official.profileName
      : 'registered Acme Financial brand profile';
  const officialPublisher = official && 'publisher' in official ? official.publisher : 'not applicable';

  const report = [
    `# Platform review request — ${finding.id}`,
    '',
    '## Summary',
    `Observed indicators are consistent with an asset that appears to use identifiers associated with ${finding.brandName || 'the protected brand'}. This request is based only on the evidence recorded below.`,
    '',
    '## Official brand asset',
    `- Asset: ${officialName}`,
    `- Publisher/developer: ${officialPublisher}`,
    '',
    '## Reported asset and URL',
    `- Name: ${finding.candidateName}`,
    `- Identifier: ${finding.identifier}`,
    `- Platform: ${finding.platform}`,
    `- URL: ${finding.url}`,
    '',
    '## Observed similarities and measured evidence',
    [evidence, logoEvidence].filter(Boolean).join('\n'),
    '',
    '## Publisher difference',
    `- Observed publisher/developer: ${finding.publisherOrDeveloper || 'not available'}`,
    `- Registered publisher: ${officialPublisher}`,
    '',
    '## Date discovered',
    `- ${finding.firstSeen}`,
    '',
    '## Analyst decision',
    `- Confirmed by ${actor}; current score ${finding.riskScore}/100 (${finding.riskLevel}).`,
    '',
    '## Signals not found',
    notFound.length ? `- No positive evidence recorded for: ${notFound.join(', ')}.` : '- All listed signal categories had recorded positive evidence.',
    '',
    '## Requested action',
    'Please review the observed information under your platform policies and take any action you determine appropriate.',
  ].join('\n');
  assertSafeReportWording(report);
  return report;
}

export function assertSafeReportWording(report: string): void {
  if (UNSUPPORTED_CLAIMS.test(report)) {
    throw new Error('Report contains an unsupported intent, fraud, or damage claim.');
  }
}
