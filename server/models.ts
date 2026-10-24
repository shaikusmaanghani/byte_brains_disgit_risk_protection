import mongoose, { Schema } from 'mongoose';

const { model, models } = mongoose;

const historyEntrySchema = new Schema({
  timestamp: { type: String, required: true },
  actor: { type: String, required: true },
  action: { type: String, required: true },
  fromStatus: String,
  toStatus: String,
  note: String,
}, { _id: false });

const evidenceSchema = new Schema({
  signal: { type: String, required: true },
  weight: Number,
  points_contributed: Number,
  reason: String,
}, { _id: false });

const userSchema = new Schema({
  id: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, index: true },
  role: { type: String, required: true },
  department: { type: String, required: true },
  avatarUrl: String,
  passwordSalt: { type: String, select: false },
  passwordHash: { type: String, select: false },
}, { strict: false, versionKey: false, minimize: false });

const detectionSchema = new Schema({
  id: { type: String, required: true, unique: true, index: true },
  brandId: { type: String, required: true, index: true },
  assetType: { type: String, required: true },
  platform: { type: String, required: true },
  identifier: { type: String, required: true },
  candidateName: { type: String, required: true },
  riskScore: { type: Number, required: true },
  riskLevel: { type: String, required: true },
  status: { type: String, required: true },
  investigationStatus: String,
  score_breakdown: { type: Schema.Types.Mixed, default: {} },
  source: { type: Schema.Types.Mixed, default: undefined },
  suspectedAsset: { type: Schema.Types.Mixed, default: undefined },
  imitates: { type: Schema.Types.Mixed, default: undefined },
  evidence: { type: [evidenceSchema], default: [] },
  scoreBreakdown: { type: Schema.Types.Mixed, default: {} },
  history: { type: [historyEntrySchema], default: [] },
}, {
  strict: false,
  versionKey: false,
  minimize: false,
  collection: 'detections',
});
detectionSchema.index({ platform: 1, identifier: 1 }, { unique: true });

const alertSchema = new Schema({
  id: { type: String, required: true, unique: true, index: true },
  stableKey: { type: String, required: true, index: true },
  dedupeKey: { type: String, required: true, unique: true },
  detectionId: { type: String, required: true, index: true },
  score: { type: Number, required: true },
  severity: { type: String, required: true },
  createdAt: { type: String, required: true },
  read: { type: Boolean, default: false },
  escalated: { type: Boolean, default: false },
}, { strict: false, versionKey: false, minimize: false });

const reportSchema = new Schema({
  id: { type: String, required: true, unique: true, index: true },
  detectionId: { type: String, required: true, index: true },
  actor: { type: String, required: true },
  content: { type: String, required: true },
  createdAt: { type: String, required: true },
}, { strict: false, versionKey: false, minimize: false });

const appStateSchema = new Schema({
  key: { type: String, required: true, unique: true },
  value: { type: Schema.Types.Mixed, required: true },
}, { strict: false, versionKey: false, minimize: false });

const sessionSchema = new Schema({
  tokenHash: { type: String, required: true, unique: true, index: true },
  userId: { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
}, { strict: false, versionKey: false, minimize: false });

export const UserModel = models.User || model('User', userSchema);
export const DetectionModel = models.Detection || model('Detection', detectionSchema);
export const AlertModel = models.Alert || model('Alert', alertSchema);
export const ReportModel = models.Report || model('Report', reportSchema);
export const AppStateModel = models.AppState || model('AppState', appStateSchema);
export const SessionModel = models.Session || model('Session', sessionSchema);

let connectionPromise: Promise<void> | undefined;
export async function connectMongo(uri = process.env.MONGODB_URI): Promise<void> {
  if (!uri) {
    throw new Error('MONGODB_URI is required. Configure it in .env before starting SentinelShield.');
  }
  if (mongoose.connection.readyState === 1) return;
  if (!connectionPromise) {
    connectionPromise = mongoose.connect(uri)
      .then(() => undefined)
      .catch((error: unknown) => {
        connectionPromise = undefined;
        throw error;
      });
  }
  await connectionPromise;
  await Promise.all([
    UserModel.init(),
    DetectionModel.init(),
    AlertModel.init(),
    ReportModel.init(),
    AppStateModel.init(),
    SessionModel.init(),
  ]);
}

export async function disconnectMongo(): Promise<void> {
  await mongoose.disconnect();
  connectionPromise = undefined;
}
