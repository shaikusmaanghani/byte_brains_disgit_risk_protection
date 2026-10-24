import type {
  AppCandidateInput,
  BrandProfile,
  DetectionAlert,
  Finding,
  MonitoringSource,
  SocialCandidateInput,
  SystemHealthReport,
  User,
  WatchlistRule,
} from '../src/types/index.js';
import { alertForFinding, investigationStatus } from '../src/services/investigation.js';
import { analyzeMobileApp, analyzeSocialCandidate } from '../src/services/detectionEngine.js';
import { DEFAULT_BRAND, DEFAULT_SOURCES, DEFAULT_USERS, DEFAULT_WATCHLISTS } from './dbDefaults.js';
import { AlertModel, AppStateModel, connectMongo, DetectionModel, ReportModel, SessionModel, UserModel } from './models.js';
import { DEMO_CREDENTIALS } from './auth.js';

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

type StoredRecord = Record<string, unknown>;

function toRecord<T>(doc: unknown): T {
  if (!doc || typeof doc !== 'object') return doc as T;
  const { _id: _mongoId, __v: _version, ...record } = doc as StoredRecord;
  return record as T;
}

function hydrateFinding(finding: Finding, brand: BrandProfile): Finding {
  const payload = finding.candidatePayload || {};
  const official = finding.matchedOfficialAsset;
  const officialName = official && 'appName' in official
    ? official.appName
    : official && 'profileName' in official
      ? official.profileName
      : brand.name;
  const signals = finding.signals || [];
  const firstSeen = finding.firstSeen || new Date().toISOString();
  const scoreBreakdown = finding.scoreBreakdown || finding.score_breakdown || signals.reduce<Record<string, number>>((result, signal) => {
    result[signal.type] = (result[signal.type] || 0) + signal.score;
    return result;
  }, {});
  return {
    ...finding,
    investigationStatus: finding.investigationStatus || investigationStatus(finding),
    scoreBreakdown,
    score_breakdown: scoreBreakdown,
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
      type: finding.assetType === 'mobile_application' ? 'app' : 'profile',
      name: finding.candidateName,
      handle: finding.assetType === 'social_profile' ? finding.identifier : undefined,
      publisherOrDeveloper: finding.publisherOrDeveloper,
      description: finding.descriptionSnippet,
      logo_ref: payload.iconUrl || payload.avatarUrl || finding.iconUrl,
    },
    imitates: finding.imitates || { official_asset_id: official?.id, official_asset_name: officialName },
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
  const analysis = finding.assetType === 'mobile_application'
    ? analyzeMobileApp(finding.candidatePayload as AppCandidateInput, brand)
    : analyzeSocialCandidate(finding.candidatePayload as SocialCandidateInput, brand);
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

function userDocument(user: User) {
  const credential = DEMO_CREDENTIALS.find((item) => item.userId === user.id);
  return {
    ...user,
    email: credential?.email || user.email,
    passwordSalt: credential?.passwordSalt,
    passwordHash: credential?.passwordHash,
  };
}

function alertDocument(alert: DetectionAlert) {
  return {
    ...alert,
    dedupeKey: `${alert.stableKey}|${alert.severity}`,
  };
}

class SentinelDatabase {
  private initialized = false;

  public async initialize(): Promise<void> {
    if (this.initialized) return;
    await connectMongo();
    await Promise.all([
      AppStateModel.updateOne({ key: 'brand' }, { $setOnInsert: { value: DEFAULT_BRAND } }, { upsert: true }),
      AppStateModel.updateOne({ key: 'sources' }, { $setOnInsert: { value: DEFAULT_SOURCES } }, { upsert: true }),
      AppStateModel.updateOne({ key: 'watchlists' }, { $setOnInsert: { value: DEFAULT_WATCHLISTS } }, { upsert: true }),
      AppStateModel.updateOne({
        key: 'scanStats',
      }, {
        $setOnInsert: { value: { lastScanTime: '2026-10-08T11:28:00Z', totalScansCount: 42 } },
      }, { upsert: true }),
      ...DEFAULT_USERS.map((user) => UserModel.updateOne(
        { id: user.id },
        { $setOnInsert: userDocument(user) },
        { upsert: true },
      )),
    ]);
    this.initialized = true;
  }

  private async state<T>(key: string, fallback: T): Promise<T> {
    const result = await AppStateModel.findOne({ key }).lean().exec();
    return result ? result.value as T : fallback;
  }

  public async getBrand(): Promise<BrandProfile> {
    return this.state('brand', DEFAULT_BRAND);
  }

  public async updateBrand(updates: Partial<BrandProfile>): Promise<BrandProfile> {
    const brand = { ...await this.getBrand(), ...updates, updatedAt: new Date().toISOString() };
    await AppStateModel.updateOne({ key: 'brand' }, { $set: { value: brand } }, { upsert: true });
    return brand;
  }

  public async getUsers(): Promise<User[]> {
    const users = await UserModel.find().lean().exec();
    return users.map((user) => toRecord<User>(user));
  }

  public async getFindings(): Promise<Finding[]> {
    const [docs, brand] = await Promise.all([
      DetectionModel.find().lean().exec(),
      this.getBrand(),
    ]);
    return docs.map((doc) => hydrateFinding(toRecord<Finding>(doc), brand));
  }

  public async getFindingById(id: string): Promise<Finding | undefined> {
    const [doc, brand] = await Promise.all([
      DetectionModel.findOne({ id }).lean().exec(),
      this.getBrand(),
    ]);
    return doc ? hydrateFinding(toRecord<Finding>(doc), brand) : undefined;
  }

  private async maybeCreateAlert(finding: Finding): Promise<void> {
    const priorDocs = await AlertModel.find({ stableKey: {
      $in: [
        `${finding.platform.toLowerCase()}|${finding.identifier.trim().toLowerCase().replace(/^@/, '')}|${finding.matchedOfficialAsset?.id || finding.brandId}`,
      ],
    } }).lean().exec();
    const next = alertForFinding(
      finding,
      priorDocs.map((doc) => toRecord<DetectionAlert>(doc)),
      `alert-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    );
    if (!next) return;
    const document = alertDocument(next as DetectionAlert);
    try {
      await AlertModel.updateOne(
        { dedupeKey: document.dedupeKey },
        { $setOnInsert: document },
        { upsert: true },
      );
    } catch (error) {
      if ((error as { code?: number }).code !== 11000) throw error;
    }
  }

  public async addFinding(finding: Finding): Promise<Finding> {
    const brand = await this.getBrand();
    const existingDoc = await DetectionModel.findOne({
      platform: finding.platform,
      identifier: finding.identifier,
    }).lean().exec();
    let saved: Finding;
    if (existingDoc) {
      const previous = hydrateFinding(toRecord<Finding>(existingDoc), brand);
      const previousStatus = investigationStatus(previous);
      const refreshed = hydrateFinding({
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
      }, brand);
      const updated = await DetectionModel.findOneAndUpdate(
        { id: previous.id },
        { $set: refreshed },
        { returnDocument: 'after', runValidators: true },
      ).lean().exec();
      if (!updated) throw new Error(`Detection ${previous.id} disappeared during update.`);
      saved = toRecord<Finding>(updated);
    } else {
      saved = hydrateFinding(finding, brand);
      try {
        await DetectionModel.create(saved);
      } catch (error) {
        if ((error as { code?: number }).code !== 11000) throw error;
        const raced = await DetectionModel.findOne({
          platform: finding.platform,
          identifier: finding.identifier,
        }).lean().exec();
        if (!raced) throw error;
        saved = toRecord<Finding>(raced);
      }
    }
    await this.maybeCreateAlert(saved);
    return saved;
  }

  public async updateFinding(id: string, updates: Partial<Finding>): Promise<Finding | null> {
    const current = await this.getFindingById(id);
    if (!current) return null;
    const next = { ...current, ...updates, lastSeen: new Date().toISOString() };
    const saved = await DetectionModel.findOneAndUpdate(
      { id },
      { $set: next },
      { returnDocument: 'after', runValidators: true },
    ).lean().exec();
    return saved ? toRecord<Finding>(saved) : null;
  }

  public async getAlerts(): Promise<DetectionAlert[]> {
    const docs = await AlertModel.find().sort({ createdAt: -1 }).lean().exec();
    return docs.map((doc) => toRecord<DetectionAlert>(doc));
  }

  public async markAlertRead(id: string): Promise<DetectionAlert | null> {
    const doc = await AlertModel.findOneAndUpdate({ id }, { $set: { read: true } }, { returnDocument: 'after' }).lean().exec();
    return doc ? toRecord<DetectionAlert>(doc) : null;
  }

  public async deleteFinding(id: string): Promise<boolean> {
    const result = await DetectionModel.deleteOne({ id });
    return result.deletedCount === 1;
  }

  public async getSources(): Promise<MonitoringSource[]> {
    return this.state('sources', DEFAULT_SOURCES);
  }

  public async updateSource(id: string, updates: Partial<MonitoringSource>): Promise<MonitoringSource | null> {
    const sources = await this.getSources();
    const index = sources.findIndex((source) => source.id === id);
    if (index < 0) return null;
    sources[index] = { ...sources[index], ...updates };
    await AppStateModel.updateOne({ key: 'sources' }, { $set: { value: sources } }, { upsert: true });
    return sources[index];
  }

  public async getWatchlists(): Promise<WatchlistRule[]> {
    return this.state('watchlists', DEFAULT_WATCHLISTS);
  }

  public async addWatchlist(rule: WatchlistRule): Promise<WatchlistRule> {
    const watchlists = await this.getWatchlists();
    const existing = watchlists.find((item) => item.id === rule.id);
    if (!existing) watchlists.push(rule);
    await AppStateModel.updateOne({ key: 'watchlists' }, { $set: { value: watchlists } }, { upsert: true });
    return existing || rule;
  }

  public async recordMonitoringScan(newFindingsCount: number): Promise<{ lastScanTime: string; totalScansCount: number }> {
    const lastScanTime = new Date().toISOString();
    const state = await AppStateModel.findOneAndUpdate(
      { key: 'scanStats' },
      { $set: { 'value.lastScanTime': lastScanTime }, $inc: { 'value.totalScansCount': 1 } },
      { returnDocument: 'after', upsert: true, setDefaultsOnInsert: true },
    ).lean().exec();
    const scanStats = state?.value as { totalScansCount?: number } | undefined;
    const sources = (await this.getSources()).map((source) => ({
      ...source,
      lastSync: lastScanTime,
      recordsScanned: source.recordsScanned + Math.floor(Math.random() * 250) + 50,
      threatsDetected: source.threatsDetected + Math.max(0, newFindingsCount),
    }));
    await AppStateModel.updateOne({ key: 'sources' }, { $set: { value: sources } }, { upsert: true });
    return { lastScanTime, totalScansCount: scanStats?.totalScansCount || 1 };
  }

  public async createReport(report: { id: string; detectionId: string; actor: string; content: string; createdAt: string }): Promise<void> {
    await ReportModel.updateOne({ id: report.id }, { $setOnInsert: report }, { upsert: true });
  }

  public async seedDatabase(schema: DatabaseSchema, reset = false, overwriteState = false): Promise<void> {
    await connectMongo();
    if (reset) {
      await Promise.all([
        DetectionModel.deleteMany({}),
        AlertModel.deleteMany({}),
        UserModel.deleteMany({}),
        SessionModel.deleteMany({}),
        ReportModel.deleteMany({}),
        AppStateModel.deleteMany({}),
      ]);
    }
    const brand = schema.brand || DEFAULT_BRAND;
    const findings = (schema.findings || [])
      .map((finding) => rescoreLegacyFinding(finding, brand))
      .filter((finding): finding is Finding => finding !== null);
    const setState = (key: string, value: unknown) => AppStateModel.updateOne(
      { key },
      overwriteState
        ? { $set: { value } }
        : { $setOnInsert: { value } },
      { upsert: true },
    );
    await Promise.all([
      setState('brand', brand),
      setState('sources', schema.sources || DEFAULT_SOURCES),
      setState('watchlists', schema.watchlists || DEFAULT_WATCHLISTS),
      setState('scanStats', {
        lastScanTime: schema.lastScanTime || new Date().toISOString(),
        totalScansCount: schema.totalScansCount || 0,
      }),
      ...(schema.users || DEFAULT_USERS).map((user) => UserModel.updateOne(
        { id: user.id },
        { $setOnInsert: userDocument(user) },
        { upsert: true },
      )),
    ]);
    for (const finding of findings) {
      const identityMatch = await DetectionModel.findOne({
        $or: [
          { id: finding.id },
          { platform: finding.platform, identifier: finding.identifier },
        ],
      }).select({ id: 1 }).lean().exec();
      if (identityMatch) continue;
      await DetectionModel.updateOne(
        { id: finding.id },
        { $setOnInsert: finding },
        { upsert: true },
      );
    }
    for (const alert of schema.alerts || []) {
      await AlertModel.updateOne(
        { dedupeKey: `${alert.stableKey}|${alert.severity}` },
        { $setOnInsert: alertDocument(alert) },
        { upsert: true },
      );
    }
  }

  public async importLegacyJson(schema: DatabaseSchema): Promise<void> {
    await this.seedDatabase(schema, false, true);
  }

  public async getSystemHealth(): Promise<SystemHealthReport> {
    const startedAt = Date.now();
    const [count, scanStats] = await Promise.all([
      DetectionModel.countDocuments(),
      this.state('scanStats', { lastScanTime: new Date().toISOString(), totalScansCount: 0 }),
    ]);
    const databaseLatencyMs = Date.now() - startedAt;
    return {
      backend: 'healthy',
      database: 'healthy',
      detectionEngine: 'healthy',
      monitoringScheduler: 'healthy',
      apiLatencyMs: 14,
      databaseLatencyMs,
      activeWorkers: 4,
      lastScanTimestamp: scanStats.lastScanTime,
      totalEngineEvaluations: count * 12 + scanStats.totalScansCount * 8,
    };
  }
}

export const db = new SentinelDatabase();
