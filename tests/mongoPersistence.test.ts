import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { db } from '../server/db.js';
import { AlertModel, DetectionModel, disconnectMongo } from '../server/models.js';
import { createDemoSession, currentUser, revokeSession } from '../server/auth.js';
import type { Finding } from '../src/types/index.js';

async function main() {
  const id = `mongo-alert-test-${randomUUID()}`;
  let stableKey = '';
  let sessionToken: string | undefined;
  try {
    await db.initialize();
    const session = await createDemoSession(
      'analyst1@sentinelshield.demo',
      'AnalystDemo2026!',
      await db.getUsers(),
    );
    assert.ok(session, 'Demo login should create a Mongo-backed session.');
    sessionToken = session.token;
    assert.equal((await currentUser(sessionToken))?.name, 'Analyst One');
    await revokeSession(sessionToken);
    assert.equal(await currentUser(sessionToken), null, 'Revoked Mongo-backed sessions must no longer authenticate.');
    console.log('✅ Mongo session persistence: login, lookup, and revocation work across requests.');

    const brand = await db.getBrand();
    const timestamp = new Date().toISOString();
    const finding: Finding = {
      id,
      brandId: brand.id,
      assetType: 'social_profile',
      platform: 'x_twitter',
      candidateName: 'SentinelShield Mongo Alert Test',
      identifier: `@mongo_alert_test_${randomUUID().replace(/-/g, '')}`,
      url: 'https://x.example/mongo-alert-test',
      riskScore: 92,
      riskLevel: 'critical',
      classification: 'high_risk_impersonation',
      confidence: 0.99,
      status: 'new',
      firstSeen: timestamp,
      lastSeen: timestamp,
      notes: [],
      signals: [],
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
      recommendedAction: 'Test record only.',
      summaryExplanation: 'Test record for Mongo alert deduplication.',
      candidatePayload: {},
      isSimulated: true,
      investigationStatus: 'New',
      scoreBreakdown: {},
      history: [],
      isOfficialAsset: false,
    };
    stableKey = [
      finding.platform,
      finding.identifier.toLowerCase().replace(/^@/, ''),
      finding.brandId,
    ].join('|');

    await db.addFinding(finding);
    await db.addFinding(finding);
    await db.addFinding(finding);

    const duplicateAlerts = await AlertModel.countDocuments({ stableKey });
    assert.equal(duplicateAlerts, 1, 'Three ingestions of the same high-risk detection must persist one alert.');
    console.log('✅ Mongo alert deduplication: three identical ingestions produced exactly one alert.');
  } finally {
    if (sessionToken) await revokeSession(sessionToken);
    if (stableKey) await AlertModel.deleteMany({ stableKey });
    await DetectionModel.deleteOne({ id });
    await disconnectMongo();
  }
}

main().catch((error: unknown) => {
  console.error('Mongo persistence integration test failed:', error);
  process.exitCode = 1;
});
