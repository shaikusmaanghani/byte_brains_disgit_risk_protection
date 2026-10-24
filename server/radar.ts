import { createHash, randomUUID } from 'node:crypto';
import type { PipelineStage } from 'mongoose';
import type {
  AppCandidateInput,
  BrandProfile,
  Finding,
  LogoComparison,
  SocialCandidateInput,
} from '../src/types/index.js';
import { analyzeMobileApp, analyzeSocialCandidate } from '../src/services/detectionEngine.js';
import { LOGO_MATCH_THRESHOLD } from '../src/services/scoringConfig.js';
import { db } from './db.js';
import {
  AppStateModel,
  DetectionModel,
  RadarLockModel,
} from './models.js';
import { compareCandidateLogo, officialLogoHashes } from './logoService.js';
import {
  collectSourceAdapters,
  defaultRadarAdapters,
  type RadarCandidate,
  type SourceAdapter,
  type SourceResult,
} from './radarSources.js';

export interface RadarSummary {
  total_suspected: number;
  confirmed_fake: number;
  by_platform: Record<string, number>;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  new_last_hour: number;
  new_last_24h: number;
  logo_matches: number;
  logo_match_threshold: number;
  top_5_highest_risk: Array<{
    id: string;
    name: string;
    platform: string;
    score: number;
    logo_similarity: number | null;
    logo_url: string | null;
    demo_data: boolean;
    status: string;
  }>;
  recent_new_ids: string[];
  last_scan_at: string | null;
  next_scan_at: string | null;
  scan_in_progress: boolean;
  sources_checked: Array<{ name: string; status: 'ok' | 'skipped' | 'failed'; detail: string }>;
}

interface RadarState {
  lastScanAt?: string;
  nextScanAt?: string;
  scanInProgress?: boolean;
  sourcesChecked?: RadarSummary['sources_checked'];
  progress?: string;
}

interface AdapterScanOptions {
  adapters?: SourceAdapter[];
  maxCandidates?: number;
  lockId?: string;
  stateKey?: string;
}

const RADAR_STATE_KEY = 'radarState';
const RADAR_LOCK_ID = 'brand-threat-radar';
const SUMMARY_CACHE_MS = 10_000;
const LOCK_MS = 55_000;
const DEFAULT_COOLDOWN_MINUTES = 10;
let cachedSummary: { expiresAt: number; value: RadarSummary } | undefined;

function cooldownMinutes(): number {
  const configured = Number(process.env.SCAN_COOLDOWN_MINUTES || DEFAULT_COOLDOWN_MINUTES);
  return Number.isFinite(configured) && configured > 0 ? Math.min(1440, configured) : DEFAULT_COOLDOWN_MINUTES;
}

function statusExpression(): Record<string, unknown> {
  return {
    $ifNull: [
      '$investigationStatus',
      {
        $switch: {
          branches: [
            { case: { $eq: ['$status', 'new'] }, then: 'New' },
            { case: { $eq: ['$status', 'investigating'] }, then: 'Under Review' },
            { case: { $eq: ['$status', 'confirmed_threat'] }, then: 'Confirmed' },
            { case: { $eq: ['$status', 'false_positive'] }, then: 'False Positive' },
            { case: { $in: ['$status', ['resolved', 'dismissed']] }, then: 'Closed' },
          ],
          default: '$status',
        },
      },
    ],
  };
}

function platformCategoryExpression(): Record<string, unknown> {
  return {
    $switch: {
      branches: [
        { case: { $eq: ['$assetType', 'mobile_application'] }, then: 'mobile app' },
        { case: { $eq: ['$assetType', 'social_profile'] }, then: 'social profile' },
        { case: { $eq: ['$assetType', 'domain'] }, then: 'web page' },
      ],
      default: 'web page',
    },
  };
}

function officialAssetExclusions(brand: BrandProfile): Record<string, unknown>[] {
  const exclusions: Record<string, unknown>[] = [];
  for (const app of brand.officialApps || []) {
    const packageId = app.packageId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    exclusions.push({
      platform: app.platform,
      identifier: { $regex: `^${packageId}$`, $options: 'i' },
    });
    if (app.storeUrl) exclusions.push({ url: app.storeUrl });
  }
  for (const account of brand.officialSocialAccounts || []) {
    const handle = account.handle.replace(/^@/, '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    exclusions.push({
      platform: account.platform,
      identifier: { $regex: `^@?${handle}$`, $options: 'i' },
    });
    if (account.profileUrl) exclusions.push({ url: account.profileUrl });
  }
  for (const domain of brand.officialDomains || []) {
    const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    exclusions.push({ assetType: 'domain', identifier: { $regex: `(^|\\.)${escaped}$`, $options: 'i' } });
    exclusions.push({
      url: { $regex: `^https?://([^/]+\\.)?${escaped}(:\\d+)?(/|$)`, $options: 'i' },
    });
  }
  return exclusions;
}

function stateValue<T>(doc: { value?: unknown } | null, fallback: T): T {
  return doc?.value as T || fallback;
}

export function invalidateRadarSummaryCache(): void {
  cachedSummary = undefined;
}

export async function getRadarSummary(
  brand: BrandProfile,
  options: { bypassCache?: boolean } = {},
): Promise<RadarSummary> {
  if (!options.bypassCache && cachedSummary && cachedSummary.expiresAt > Date.now()) {
    return cachedSummary.value;
  }
  const now = new Date();
  const hourAgo = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
  const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const activeStatuses = ['New', 'Under Review', 'Confirmed'];
  const suspectedStatuses = ['New', 'Under Review'];
  const baseStages: PipelineStage[] = [
    {
      $match: {
        brandId: brand.id,
        isOfficialAsset: { $ne: true },
        $nor: officialAssetExclusions(brand),
      },
    },
    {
      $addFields: {
        radarStatus: statusExpression(),
        radarLogoSimilarity: '$logoComparison.similarity',
      },
    },
  ];
  const pipeline: PipelineStage[] = [
    ...baseStages,
    {
      $facet: {
        headline: [
          { $match: { radarStatus: { $in: activeStatuses } } },
          {
            $group: {
              _id: null,
              total_suspected: { $sum: { $cond: [{ $in: ['$radarStatus', suspectedStatuses] }, 1, 0] } },
              confirmed_fake: { $sum: { $cond: [{ $eq: ['$radarStatus', 'Confirmed'] }, 1, 0] } },
              logo_matches: {
                $sum: {
                  $cond: [
                    { $gte: ['$radarLogoSimilarity', LOGO_MATCH_THRESHOLD] },
                    1,
                    0,
                  ],
                },
              },
            },
          },
        ],
        platforms: [
          { $match: { radarStatus: { $in: activeStatuses } } },
          { $group: { _id: platformCategoryExpression(), count: { $sum: 1 } } },
        ],
        severities: [
          { $match: { radarStatus: { $in: activeStatuses } } },
          { $group: { _id: '$riskLevel', count: { $sum: 1 } } },
        ],
        statuses: [
          { $match: { radarStatus: { $in: activeStatuses } } },
          { $group: { _id: '$radarStatus', count: { $sum: 1 } } },
        ],
        newCounts: [
          { $match: { radarStatus: 'New' } },
          {
            $group: {
              _id: null,
              lastHour: { $sum: { $cond: [{ $gte: ['$firstSeen', hourAgo] }, 1, 0] } },
              last24h: { $sum: { $cond: [{ $gte: ['$firstSeen', dayAgo] }, 1, 0] } },
            },
          },
        ],
        top: [
          { $match: { radarStatus: { $in: activeStatuses } } },
          { $sort: { riskScore: -1, lastSeen: -1 } },
          { $limit: 5 },
          {
            $project: {
              _id: 0,
              id: 1,
              name: '$candidateName',
              platform: platformCategoryExpression(),
              score: '$riskScore',
              logo_similarity: { $ifNull: ['$radarLogoSimilarity', null] },
              logo_url: { $ifNull: ['$iconUrl', null] },
              demo_data: { $eq: ['$isSimulated', true] },
              status: '$radarStatus',
            },
          },
        ],
        recentNew: [
          { $match: { radarStatus: 'New', firstSeen: { $gte: hourAgo } } },
          { $sort: { firstSeen: -1 } },
          { $limit: 100 },
          { $project: { _id: 0, id: 1 } },
        ],
      },
    },
  ];
  const [aggregate] = await DetectionModel.aggregate(pipeline).exec();
  const [stateDoc, activeLock] = await Promise.all([
    AppStateModel.findOne({ key: RADAR_STATE_KEY }).lean().exec(),
    RadarLockModel.findOne({ _id: RADAR_LOCK_ID, expiresAt: { $gt: now } }).lean().exec(),
  ]);
  const state = stateValue<RadarState>(stateDoc, {});
  const headline = aggregate?.headline?.[0] || {};
  const newCounts = aggregate?.newCounts?.[0] || {};
  const mapCounts = (entries: Array<{ _id: string; count: number }> = []) =>
    Object.fromEntries(entries.map((entry) => [entry._id || 'unknown', entry.count]));
  const summary: RadarSummary = {
    total_suspected: headline.total_suspected || 0,
    confirmed_fake: headline.confirmed_fake || 0,
    by_platform: mapCounts(aggregate?.platforms),
    by_severity: mapCounts(aggregate?.severities),
    by_status: mapCounts(aggregate?.statuses),
    new_last_hour: newCounts.lastHour || 0,
    new_last_24h: newCounts.last24h || 0,
    logo_matches: headline.logo_matches || 0,
    logo_match_threshold: LOGO_MATCH_THRESHOLD,
    top_5_highest_risk: aggregate?.top || [],
    recent_new_ids: (aggregate?.recentNew || []).map((entry: { id: string }) => entry.id),
    last_scan_at: state.lastScanAt || null,
    next_scan_at: state.nextScanAt || null,
    scan_in_progress: Boolean(activeLock),
    sources_checked: state.sourcesChecked || [],
  };
  cachedSummary = { expiresAt: Date.now() + SUMMARY_CACHE_MS, value: summary };
  return summary;
}

function isOfficialCandidate(candidate: RadarCandidate, brand: BrandProfile): boolean {
  const identifier = candidate.identifier.replace(/^@/, '').toLowerCase();
  if (candidate.assetType === 'mobile_application') {
    return brand.officialApps.some((app) =>
      app.platform === candidate.platform &&
      (app.packageId.toLowerCase() === candidate.identifier.toLowerCase() ||
        (app.storeUrl && app.storeUrl === candidate.url)),
    );
  }
  if (candidate.assetType === 'social_profile') {
    return brand.officialSocialAccounts.some((account) =>
      account.platform === candidate.platform &&
      account.handle.replace(/^@/, '').toLowerCase() === identifier,
    );
  }
  if (candidate.assetType === 'domain') {
    const host = new URL(candidate.url).hostname.toLowerCase();
    return (brand.officialDomains || []).some((domain) => host === domain || host.endsWith(`.${domain}`));
  }
  return false;
}

function appInput(candidate: RadarCandidate, logoComparison?: LogoComparison, logoUnavailableReason?: string): AppCandidateInput {
  return {
    appName: candidate.name,
    developer: candidate.publisher || '',
    publisher: candidate.publisher || '',
    packageId: candidate.identifier,
    description: candidate.description,
    platform: candidate.platform === 'apple_app_store' ? 'apple_app_store' : 'google_play',
    storeUrl: candidate.url,
    iconUrl: candidate.logoUrl,
    website: candidate.url,
    logoComparison,
    logoUnavailableReason,
  };
}

function socialInput(candidate: RadarCandidate, logoComparison?: LogoComparison, logoUnavailableReason?: string): SocialCandidateInput {
  const payload = candidate.payload;
  const username = String(payload.username || candidate.identifier.replace(/^@/, ''));
  return {
    platform: candidate.platform,
    profileName: candidate.name,
    username,
    biography: candidate.description,
    profileUrl: candidate.url,
    avatarUrl: candidate.logoUrl,
    links: [candidate.url],
    verified: Boolean(payload.verified),
    logoComparison,
    logoUnavailableReason,
  };
}

function findingFromCandidate(
  candidate: RadarCandidate,
  brand: BrandProfile,
  analysis: ReturnType<typeof analyzeSocialCandidate>,
  logoComparison?: LogoComparison,
): Finding {
  const timestamp = new Date().toISOString();
  const stableId = createHash('sha256')
    .update(`${candidate.platform}|${candidate.identifier.toLowerCase()}|${brand.id}`)
    .digest('hex')
    .slice(0, 24);
  const candidatePayload = {
    ...candidate.payload,
    name: candidate.name,
    description: candidate.description,
    logoUrl: candidate.logoUrl,
    iconUrl: candidate.logoUrl,
    avatarUrl: candidate.logoUrl,
    logoComparison,
  };
  return {
    id: `find-radar-${stableId}`,
    brandId: brand.id,
    brandName: brand.name,
    assetType: candidate.assetType,
    platform: candidate.platform,
    candidateName: candidate.name,
    identifier: candidate.identifier,
    url: candidate.url,
    iconUrl: candidate.logoUrl,
    publisherOrDeveloper: candidate.publisher,
    descriptionSnippet: candidate.description,
    riskScore: analysis.riskScore,
    riskLevel: analysis.riskLevel,
    classification: analysis.classification,
    confidence: analysis.confidence,
    status: 'new',
    firstSeen: timestamp,
    lastSeen: timestamp,
    notes: [],
    signals: analysis.signals,
    radarBreakdown: analysis.radarBreakdown,
    recommendedAction: analysis.recommendedAction,
    summaryExplanation: analysis.summaryExplanation,
    matchedOfficialAsset: analysis.matchedOfficialAsset,
    candidatePayload,
    isSimulated: Boolean(candidate.isDemo),
    investigationStatus: 'New',
    scoreBreakdown: analysis.scoreBreakdown || {},
    history: [{
      timestamp,
      actor: candidate.isDemo ? 'Demo seed' : 'Detection engine',
      action: 'Detection created',
      toStatus: 'New',
      note: candidate.isDemo ? 'Existing demo seed record; not live intelligence.' : `Detected by ${candidate.source} source adapter.`,
    }],
    isOfficialAsset: false,
    source: {
      platform: candidate.platform,
      url: candidate.url,
      identifier: candidate.identifier,
      discovered_at: timestamp,
      name: candidate.source,
      kind: candidate.isDemo ? 'demo' : 'live',
    },
    logoComparison,
    logoMatchThreshold: Number(process.env.LOGO_MATCH_THRESHOLD || LOGO_MATCH_THRESHOLD),
  };
}

async function evaluateCandidate(candidate: RadarCandidate, brand: BrandProfile, hashes: Awaited<ReturnType<typeof officialLogoHashes>>) {
  if (isOfficialCandidate(candidate, brand)) return null;
  const logoResult = await compareCandidateLogo(candidate.logoUrl, hashes);
  const updatedBrand: BrandProfile = hashes.length
    ? { ...brand, logoHash: hashes[0].dHash }
    : brand;
  const analysis = candidate.assetType === 'mobile_application'
    ? analyzeMobileApp(
      appInput(candidate, logoResult.comparison, logoResult.reason),
      updatedBrand,
    )
    : analyzeSocialCandidate(
      socialInput(candidate, logoResult.comparison, logoResult.reason),
      updatedBrand,
    );
  if (analysis.isOfficialAsset) return null;
  return db.addFinding(findingFromCandidate(candidate, brand, analysis, logoResult.comparison));
}

function sourceStatus(results: SourceResult[]): RadarSummary['sources_checked'] {
  return results.map(({ name, status, detail }) => ({ name, status, detail }));
}

async function writeRadarState(state: RadarState, stateKey = RADAR_STATE_KEY): Promise<void> {
  await AppStateModel.updateOne(
    { key: stateKey },
    { $set: { value: state } },
    { upsert: true },
  );
  invalidateRadarSummaryCache();
}

async function acquireScanLock(lockId = RADAR_LOCK_ID): Promise<string | null> {
  const owner = randomUUID();
  try {
    const lock = await RadarLockModel.findOneAndUpdate(
      { _id: lockId, expiresAt: { $lte: new Date() } },
      { $set: { owner, expiresAt: new Date(Date.now() + LOCK_MS) } },
      { upsert: true, returnDocument: 'after' },
    ).lean().exec();
    return lock?.owner === owner ? owner : null;
  } catch (error) {
    if ((error as { code?: number }).code === 11000) return null;
    throw error;
  }
}

export async function runRadarScan(
  brand: BrandProfile,
  options: AdapterScanOptions = {},
): Promise<{ started: boolean; scan_in_progress: boolean; last_scan_at: string | null; sources_checked: RadarSummary['sources_checked'] }> {
  const lockId = options.lockId || RADAR_LOCK_ID;
  const stateKey = options.stateKey || RADAR_STATE_KEY;
  const now = new Date();
  const [activeLock, stateDoc] = await Promise.all([
    RadarLockModel.findOne({ _id: lockId, expiresAt: { $gt: now } }).lean().exec(),
    AppStateModel.findOne({ key: stateKey }).lean().exec(),
  ]);
  const previousState = stateValue<RadarState>(stateDoc, {});
  if (activeLock) {
    return {
      started: false,
      scan_in_progress: true,
      last_scan_at: previousState.lastScanAt || null,
      sources_checked: previousState.sourcesChecked || [],
    };
  }
  const cooldownMs = cooldownMinutes() * 60_000;
  const previousTime = previousState.lastScanAt ? Date.parse(previousState.lastScanAt) : 0;
  if (previousTime && Date.now() - previousTime < cooldownMs) {
    return {
      started: false,
      scan_in_progress: false,
      last_scan_at: previousState.lastScanAt || null,
      sources_checked: previousState.sourcesChecked || [],
    };
  }
  const owner = await acquireScanLock(lockId);
  if (!owner) {
    return {
      started: false,
      scan_in_progress: true,
      last_scan_at: previousState.lastScanAt || null,
      sources_checked: previousState.sourcesChecked || [],
    };
  }
  const initialState: RadarState = {
    ...previousState,
    scanInProgress: true,
    progress: 'Loading source adapters',
    sourcesChecked: [],
  };
  await writeRadarState(initialState, stateKey);
  try {
    const existingFindings = await db.getFindings();
    const adapters = options.adapters || defaultRadarAdapters(existingFindings);
    const results = await collectSourceAdapters(brand, adapters);
    const checked = sourceStatus(results);
    const pendingState = {
      ...initialState,
      progress: `Collected ${results.reduce((sum, result) => sum + result.candidates.length, 0)} source candidates`,
      sourcesChecked: checked,
    };
    await writeRadarState(pendingState, stateKey);
    const candidates = results.flatMap((result) => result.candidates.slice(0, 4));
    const selected = candidates.slice(0, options.maxCandidates || 20);
    const officialHashes = selected.some((candidate) => candidate.logoUrl)
      ? await officialLogoHashes(brand)
      : [];
    let processed = 0;
    for (let index = 0; index < selected.length; index += 4) {
      const batch = selected.slice(index, index + 4);
      await Promise.all(batch.map((candidate) => evaluateCandidate(candidate, brand, officialHashes)));
      processed += batch.length;
      await writeRadarState({
        ...pendingState,
        progress: `Scored ${processed} of ${selected.length} candidate records`,
      }, stateKey);
    }
    const lastScanAt = new Date().toISOString();
    const nextScanAt = new Date(Date.now() + cooldownMs).toISOString();
    await writeRadarState({
      lastScanAt,
      nextScanAt,
      scanInProgress: false,
      progress: 'Complete',
      sourcesChecked: checked,
    }, stateKey);
    return {
      started: true,
      scan_in_progress: false,
      last_scan_at: lastScanAt,
      sources_checked: checked,
    };
  } catch (error) {
    await writeRadarState({
      ...initialState,
      scanInProgress: false,
      progress: 'Failed',
      sourcesChecked: [
        ...(previousState.sourcesChecked || []),
        { name: 'Radar scan', status: 'failed', detail: error instanceof Error ? error.message : 'Scan failed.' },
      ],
    }, stateKey);
    throw error;
  } finally {
    await RadarLockModel.deleteOne({ _id: lockId, owner });
    invalidateRadarSummaryCache();
  }
}
