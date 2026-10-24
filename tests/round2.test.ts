import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { DEFAULT_BRAND } from '../server/dbDefaults';
import {
  analyzeMobileApp,
  analyzeSocialCandidate,
  perceptualHashDistance,
} from '../src/services/detectionEngine';
import { alertForFinding } from '../src/services/investigation';
import { transitionFinding } from '../src/services/investigation';
import { draftTakedownReport, assertSafeReportWording } from '../src/services/takedownReport';
import { answerAnalystQuestion } from '../src/services/analystAssistant';
import type { DatabaseSchema } from '../server/db';
import type { DetectionAlert, Finding } from '../src/types';

const persisted = JSON.parse(readFileSync(path.resolve(process.cwd(), 'data', 'sentinel_db.json'), 'utf8')) as DatabaseSchema;
const brand = persisted.brand || DEFAULT_BRAND;
const findings = persisted.findings as Finding[];

const clone = analyzeMobileApp({
  appName: 'Acme Mobile Banking',
  developer: 'Rogue Apps LLC',
  publisher: 'Rogue Apps LLC',
  packageId: 'com.fake.acme.bank',
  platform: 'google_play',
  description: 'Official Acme secure banking application. Verify your account and receive rewards. Fast money transfers.',
  website: 'https://acme-login-check.xyz',
}, brand);
assert.ok(clone.riskScore >= 85, `Near-identical, unapproved app should score >=85; received ${clone.riskScore}`);
assert.ok(clone.signals.some((signal) => signal.type === 'logo_comparison_skipped'));
assert.ok(clone.scoreBreakdown);

const loose = analyzeMobileApp({
  appName: 'Acme FinTech Pay',
  developer: 'Local Tools',
  publisher: 'Local Tools',
  packageId: 'com.local.pay',
  platform: 'google_play',
  description: 'A personal budget notebook with tips for saving money.',
}, brand);
assert.ok(loose.riskScore >= 30 && loose.riskScore <= 55, `Loose resemblance should score 30–55; received ${loose.riskScore}`);

const unrelated = analyzeMobileApp({
  appName: 'SunnyDay Weather Forecast',
  developer: 'Sky Met',
  publisher: 'Sky Met',
  packageId: 'com.sky.weather',
  platform: 'google_play',
  description: 'Seven day rain and temperature forecast.',
}, brand);
assert.ok(unrelated.riskScore < 20, `Unrelated asset should remain below 20; received ${unrelated.riskScore}`);

const official = brand.officialApps[0];
const allowlisted = analyzeMobileApp({
  appName: official.appName,
  developer: official.developer,
  publisher: official.publisher,
  packageId: official.packageId,
  platform: official.platform,
  description: 'Official Acme account services.',
}, brand);
assert.equal(allowlisted.isOfficialAsset, true, 'Official allowlisted apps are excluded before threat scoring.');
assert.equal(allowlisted.riskScore, 0);

const fanPage = analyzeSocialCandidate({
  platform: 'facebook',
  username: 'acme_fan_club',
  profileName: 'Acme Financial Fan Club',
  biography: 'An independent fan community sharing publicly available company news. Not affiliated with Acme Financial.',
}, brand);
assert.ok(fanPage.riskScore >= 30 && fanPage.riskScore <= 55, `Harmless fan page should have a low score; received ${fanPage.riskScore}`);

assert.equal(perceptualHashDistance('ffffffffffffffff', '0000000000000000'), 64);
assert.equal(perceptualHashDistance('0000000000000000', '0000000000000000'), 0);
assert.equal(perceptualHashDistance('not-a-hash', '0000000000000000'), null);

const firstFinding = findings[0];
assert.ok(firstFinding, 'Seed database must provide findings for workflow tests.');
const highRiskFinding = { ...firstFinding, riskScore: 80, riskLevel: 'high' as const, status: 'new' as const, investigationStatus: 'New' as const };
const alerts: DetectionAlert[] = [];
for (let index = 0; index < 3; index++) {
  const alert = alertForFinding(highRiskFinding, alerts, `alert-${index}`, '2026-10-24T00:00:00Z');
  if (alert) alerts.push(alert);
}
assert.equal(alerts.length, 1, 'Reingesting the same high-risk finding three times must create one alert.');
const escalated = alertForFinding(
  { ...highRiskFinding, riskScore: 90, riskLevel: 'critical' },
  alerts,
  'alert-escalated',
);
assert.equal(escalated?.escalated, true, 'A higher severity tier should produce one escalation alert.');

const reviewing = transitionFinding(highRiskFinding, 'Under Review', 'Analyst One', 'Started evidence review.', '2026-10-24T00:00:00Z');
assert.equal(reviewing.investigationStatus, 'Under Review');
assert.equal(reviewing.history?.at(-1)?.actor, 'Analyst One');
const closed = transitionFinding(reviewing, 'Closed', 'Analyst One', 'Review completed.', '2026-10-24T00:01:00Z');
assert.throws(
  () => transitionFinding(closed, 'New', 'Analyst One', 'Reopen without explicit action.', '2026-10-24T00:02:00Z'),
  /Invalid status transition/,
);
assert.equal(
  transitionFinding(closed, 'Under Review', 'Analyst One', 'Reopened for new evidence.', '2026-10-24T00:03:00Z').history?.at(-1)?.action,
  'Reopened',
);

const confirmed = findings.find((finding) => finding.status === 'confirmed_threat');
assert.ok(confirmed, 'A confirmed demo detection is needed for report tests.');
const report = draftTakedownReport(confirmed, 'Analyst One');
assert.match(report, /observed/i);
assert.match(report, /Signals not found/i);
assertSafeReportWording(report);
const measuredLogoReport = draftTakedownReport({
  ...confirmed,
  logoComparison: {
    similarity: 92,
    method: 'pHash+dHash+color histogram',
    pHashDistance: 4,
    dHashDistance: 3,
    colorHistogramSimilarity: 95,
  },
  logoMatchThreshold: 80,
  signals: confirmed.signals.filter((signal) => signal.type !== 'logo_similarity'),
}, 'Analyst One');
assert.match(measuredLogoReport, /appears visually similar at 92%/i);
assert.match(measuredLogoReport, /pHash distance 4, dHash distance 3/);
assert.match(measuredLogoReport, /pHash\+dHash\+color histogram/);
assertSafeReportWording(measuredLogoReport);
assert.throws(() => assertSafeReportWording('This is confirmed fraud.'), /unsupported/i);
assert.throws(
  () => draftTakedownReport({ ...confirmed, status: 'new', investigationStatus: 'New' }, 'Analyst One'),
  /only for Confirmed/i,
);

const answer = answerAnalystQuestion('Why is #1 scored?', findings, 'Analyst One');
assert.match(answer, /Detection find-/);
assert.match(answer, /points/);
const actorHistoryFinding = {
  ...firstFinding,
  history: [{
    timestamp: '2026-10-24T00:00:00Z',
    actor: 'Analyst One',
    action: 'Started review',
  }],
};
assert.match(
  answerAnalystQuestion('What did analyst1 do on #1?', [actorHistoryFinding], 'Analyst Two'),
  /Analyst One — Started review/,
);
assert.match(
  answerAnalystQuestion(`What did analyst1 do on ${actorHistoryFinding.id}?`, [actorHistoryFinding], 'Analyst Two'),
  /Analyst One — Started review/,
);
assert.equal(answerAnalystQuestion('Tell me a joke', [], 'Analyst One'), "I don't have data on that.");

console.log('✅ Round 2 scoring, allowlist, workflow-alert, report wording, and grounded assistant tests passed.');
