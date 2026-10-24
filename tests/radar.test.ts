import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Jimp, JimpMime } from 'jimp';
import { db } from '../server/db.js';
import {
  AppStateModel,
  AlertModel,
  DetectionModel,
  RadarLockModel,
  disconnectMongo,
} from '../server/models.js';
import { compareCandidateLogo, compareImageBuffers } from '../server/logoService.js';
import { getRadarSummary, runRadarScan } from '../server/radar.js';
import { collectSourceAdapters, type RadarCandidate, type SourceAdapter } from '../server/radarSources.js';
import { assertResponseSize, safeGet } from '../server/safeHttp.js';
import { analyzeMobileApp } from '../src/services/detectionEngine.js';
import type { BrandProfile } from '../src/types/index.js';

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function makeImage(pattern: 'bands' | 'checker'): Promise<Buffer> {
  const image = new Jimp({ width: 64, height: 64, color: 0xffffffff });
  for (let y = 0; y < 64; y++) {
    for (let x = 0; x < 64; x++) {
      const offset = (y * 64 + x) * 4;
      const band = x < 32;
      const checker = (Math.floor(x / 4) + Math.floor(y / 4)) % 2 === 0;
      const color = pattern === 'bands'
        ? (band ? [10, 30, 210] : [240, 190, 20])
        : (checker ? [15, 210, 65] : [190, 20, 170]);
      image.bitmap.data[offset] = color[0];
      image.bitmap.data[offset + 1] = color[1];
      image.bitmap.data[offset + 2] = color[2];
      image.bitmap.data[offset + 3] = 255;
    }
  }
  return image.getBuffer(JimpMime.png);
}

async function main() {
  const testIds: string[] = [];
  const testBrandIds: string[] = [];
  const stateKeys: string[] = [];
  const lockIds: string[] = [];
  const previousCooldown = process.env.SCAN_COOLDOWN_MINUTES;

  try {
    const brand = await db.initialize().then(() => db.getBrand());
    const customBrand: BrandProfile = {
      ...brand,
      id: `radar-test-${randomUUID()}`,
      officialDomains: [],
      officialApps: [{
        ...brand.officialApps[0],
        id: `official-${randomUUID()}`,
        packageId: `com.radar.official.${randomUUID().replace(/-/g, '')}`,
        storeUrl: `https://apps.example/${randomUUID()}`,
      }],
      officialSocialAccounts: [],
    };
    testBrandIds.push(customBrand.id);
    const identical = await makeImage('bands');
    const unrelated = await makeImage('checker');
    const sameResult = await compareImageBuffers(identical, identical);
    const differentResult = await compareImageBuffers(identical, unrelated);
    assert.ok(sameResult.similarity >= 95, 'Identical logo images should score at least 95% similarity.');
    assert.ok(differentResult.similarity < 40, `Unrelated patterns should score below 40% (received ${differentResult.similarity}).`);
    const missingLogo = await compareCandidateLogo(undefined, []);
    assert.match(missingLogo.reason || '', /Logo not available/);

    const noLogoAnalysis = analyzeMobileApp({
      appName: brand.officialApps[0]?.appName || brand.name,
      developer: 'Unrelated Publisher',
      publisher: 'Unrelated Publisher',
      packageId: `com.radar.no-logo.${randomUUID()}`,
      description: 'Official banking account login and verify your account.',
      platform: 'google_play',
    }, brand);
    const skippedSignal = noLogoAnalysis.signals.find((signal) => signal.type === 'logo_comparison_skipped');
    assert.ok(skippedSignal && skippedSignal.score === 0);
    assert.match(skippedSignal.explanation, /Logo not available/);
    const measuredAnalysis = analyzeMobileApp({
      appName: brand.officialApps[0]?.appName || brand.name,
      developer: 'Unrelated Publisher',
      publisher: 'Unrelated Publisher',
      packageId: `com.radar.visual.${randomUUID()}`,
      description: 'Mobile banking service.',
      platform: 'google_play',
      logoComparison: {
        similarity: 92,
        method: 'pHash+dHash+color histogram',
        pHashDistance: 4,
        dHashDistance: 3,
        colorHistogramSimilarity: 95,
      },
    }, brand);
    const logoSignal = measuredAnalysis.signals.find((signal) => signal.type === 'logo_similarity');
    assert.equal(logoSignal?.score, 9);
    assert.match(logoSignal?.explanation || '', /Logo is 92% visually similar.*pHash distance 4, dHash distance 3/);
    assert.throws(() => assertResponseSize(11, 10), /size limit/);
    await assert.rejects(() => safeGet('http://127.0.0.1/', 1024), /private|invalid IP/i);
    await assert.rejects(() => safeGet('http://[::1]/', 1024), /private|invalid IP/i);
    await assert.rejects(() => safeGet('http://[0:0:0:0:0:0:0:1]/', 1024), /private|invalid IP/i);
    await assert.rejects(() => safeGet('http://[::ffff:7f00:1]/', 1024), /private|invalid IP/i);
    await assert.rejects(() => safeGet('http://[2001:db8::1]/', 1024), /private|invalid IP/i);
    console.log('✅ Logo comparison: identical logos score ≥95, unrelated logos <40, and missing images are skipped.');
    console.log('✅ SSRF and size guards: private IPv4/IPv6 targets and oversized responses are rejected.');

    const ids = [
      `radar-summary-new-${randomUUID()}`,
      `radar-summary-confirmed-${randomUUID()}`,
      `radar-summary-fp-${randomUUID()}`,
      `radar-summary-closed-${randomUUID()}`,
      `radar-summary-official-${randomUUID()}`,
    ];
    testIds.push(...ids);
    const officialIdentifier = customBrand.officialApps[0].packageId;
    const docs = [
      { id: ids[0], identifier: `@${ids[0]}`, status: 'new', investigationStatus: 'New', riskLevel: 'high', logoComparison: { similarity: 92, method: 'pHash+dHash+color histogram', pHashDistance: 2, dHashDistance: 3, colorHistogramSimilarity: 90 } },
      { id: ids[1], identifier: `@${ids[1]}`, status: 'confirmed_threat', investigationStatus: 'Confirmed', riskLevel: 'critical', logoComparison: { similarity: 79, method: 'pHash+dHash+color histogram', pHashDistance: 12, dHashDistance: 11, colorHistogramSimilarity: 71 } },
      { id: ids[2], identifier: `@${ids[2]}`, status: 'false_positive', investigationStatus: 'False Positive', riskLevel: 'high' },
      { id: ids[3], identifier: `@${ids[3]}`, status: 'resolved', investigationStatus: 'Closed', riskLevel: 'medium' },
      { id: ids[4], identifier: officialIdentifier, status: 'new', investigationStatus: 'New', riskLevel: 'critical' },
    ].map((item, index) => ({
      ...item,
      brandId: customBrand.id,
      assetType: 'mobile_application',
      platform: index === 4 ? customBrand.officialApps[0].platform : 'google_play',
      candidateName: `Radar test ${index}`,
      riskScore: 91 - index,
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      isOfficialAsset: false,
    }));
    await DetectionModel.insertMany(docs);
    const initialSummary = await getRadarSummary(customBrand, { bypassCache: true });
    assert.equal(initialSummary.total_suspected, 1);
    assert.equal(initialSummary.confirmed_fake, 1);
    assert.equal(initialSummary.logo_matches, 1);
    assert.equal(initialSummary.by_platform['mobile app'], 2);
    await DetectionModel.updateOne(
      { id: ids[0] },
      { $set: { status: 'false_positive', investigationStatus: 'False Positive' } },
    );
    const changedSummary = await getRadarSummary(customBrand, { bypassCache: true });
    assert.equal(changedSummary.total_suspected, 0, 'Marking a suspected record false positive must lower the live count.');
    assert.equal(changedSummary.confirmed_fake, 1);
    console.log('✅ Mongo summary: allowlisted, False Positive, and Closed records are excluded; status changes update counts.');

    const skippedAdapter: SourceAdapter = {
      name: 'Radar test skipped source',
      async fetchCandidates() {
        return { name: this.name, status: 'skipped', detail: 'No source configured.', candidates: [] };
      },
    };
    const failingAdapters: SourceAdapter[] = [{
      name: 'Radar test failing source',
      async fetchCandidates() {
        throw new Error('Expected isolated adapter failure.');
      },
    }, skippedAdapter];
    const collected = await collectSourceAdapters(customBrand, failingAdapters);
    assert.deepEqual(collected.map((item) => item.status), ['failed', 'skipped']);
    const failingState = `radar-state-${randomUUID()}`;
    const failingLock = `radar-lock-${randomUUID()}`;
    stateKeys.push(failingState);
    lockIds.push(failingLock);
    const failureScan = await runRadarScan(customBrand, {
      adapters: failingAdapters,
      lockId: failingLock,
      stateKey: failingState,
    });
    assert.equal(failureScan.started, true);
    assert.equal(failureScan.sources_checked[0].status, 'failed');
    console.log('✅ Source isolation: a failed adapter is reported and does not reject the scan batch.');

    const cooldownId = `radar-lock-${randomUUID()}`;
    const cooldownState = `radar-state-${randomUUID()}`;
    stateKeys.push(cooldownState);
    lockIds.push(cooldownId);
    const cooldownFirst = await runRadarScan(customBrand, {
      adapters: [skippedAdapter],
      lockId: cooldownId,
      stateKey: cooldownState,
    });
    const cooldownSecond = await runRadarScan(customBrand, {
      adapters: [skippedAdapter],
      lockId: cooldownId,
      stateKey: cooldownState,
    });
    assert.equal(cooldownFirst.started, true);
    assert.equal(cooldownSecond.started, false, 'A second request within the cooldown must not start another scan.');

    const concurrentLock = `radar-lock-${randomUUID()}`;
    const concurrentState = `radar-state-${randomUUID()}`;
    stateKeys.push(concurrentState);
    lockIds.push(concurrentLock);
    let adapterCalls = 0;
    const slowAdapter: SourceAdapter = {
      name: 'Radar test concurrent source',
      async fetchCandidates() {
        adapterCalls++;
        await delay(150);
        return { name: this.name, status: 'ok', detail: 'No test candidates.', candidates: [] };
      },
    };
    const concurrent = await Promise.all([
      runRadarScan(customBrand, { adapters: [slowAdapter], lockId: concurrentLock, stateKey: concurrentState }),
      runRadarScan(customBrand, { adapters: [slowAdapter], lockId: concurrentLock, stateKey: concurrentState }),
    ]);
    assert.equal(concurrent.filter((result) => result.started).length, 1);
    assert.equal(adapterCalls, 1, 'Concurrent visitors should cause exactly one source adapter run.');
    console.log('✅ Scan lock and cooldown: concurrent scans collapse to one and cooldown blocks immediate retries.');

    process.env.SCAN_COOLDOWN_MINUTES = '0.000001';
    const ingestBrand: BrandProfile = { ...brand, id: `radar-ingest-${randomUUID()}` };
    testBrandIds.push(ingestBrand.id);
    const ingestState = `radar-state-${randomUUID()}`;
    const ingestLock = `radar-lock-${randomUUID()}`;
    stateKeys.push(ingestState);
    lockIds.push(ingestLock);
    const identifier = `com.radar.ingest.${randomUUID().replace(/-/g, '')}`;
    const candidate: RadarCandidate = {
      source: 'radar_test',
      assetType: 'mobile_application',
      platform: 'google_play',
      identifier,
      name: brand.officialApps[0]?.appName || `${brand.name} Banking`,
      url: 'https://apps.example/radar-test',
      description: `${brand.name} official mobile banking. Verify your account login and access online banking.`,
      publisher: 'Unrelated Publisher LLC',
      payload: {},
    };
    const candidateAdapter: SourceAdapter = {
      name: 'Radar test candidate',
      async fetchCandidates() {
        return { name: this.name, status: 'ok', detail: 'One controlled test candidate.', candidates: [candidate] };
      },
    };
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt) await delay(10);
      const result = await runRadarScan(ingestBrand, {
        adapters: [candidateAdapter],
        lockId: ingestLock,
        stateKey: ingestState,
      });
      assert.equal(result.started, true);
    }
    const persisted = await DetectionModel.find({ brandId: ingestBrand.id, platform: candidate.platform, identifier }).lean();
    testIds.push(...persisted.map((record) => record.id));
    assert.equal(persisted.length, 1);
    assert.ok(persisted[0].riskScore >= 75, 'The controlled lookalike candidate should cross the high-risk threshold.');
    const alerts = await AlertModel.countDocuments({ detectionId: persisted[0].id });
    assert.equal(alerts, 1, 'Repeated detection scans must not create duplicate alerts.');
    console.log('✅ Re-scan deduplication: three ingestions persist one detection and at most one high-risk alert.');
  } finally {
    if (previousCooldown === undefined) delete process.env.SCAN_COOLDOWN_MINUTES;
    else process.env.SCAN_COOLDOWN_MINUTES = previousCooldown;
    for (const key of stateKeys) await AppStateModel.deleteOne({ key });
    for (const id of lockIds) await RadarLockModel.deleteOne({ _id: id });
    const cleanupIds = [...new Set([
      ...testIds,
      ...await DetectionModel.distinct('id', { brandId: { $in: testBrandIds } }),
    ])];
    if (cleanupIds.length) {
      await AlertModel.deleteMany({ detectionId: { $in: cleanupIds } });
      await DetectionModel.deleteMany({ id: { $in: cleanupIds } });
    }
    await disconnectMongo();
  }
}

main().catch((error: unknown) => {
  console.error('Brand Threat Radar tests failed:', error);
  process.exitCode = 1;
});
