import type {
  Finding,
  InvestigationHistoryEntry,
  InvestigationStatus,
  RiskLevel,
} from '../types/index.js';
import { HIGH_THRESHOLD, severityForScore } from './scoringConfig.js';

const LEGACY_TO_STATUS: Record<Finding['status'], InvestigationStatus> = {
  new: 'New',
  investigating: 'Under Review',
  confirmed_threat: 'Confirmed',
  false_positive: 'False Positive',
  resolved: 'Closed',
  dismissed: 'Closed',
};

const STATUS_TO_LEGACY: Record<InvestigationStatus, Finding['status']> = {
  New: 'new',
  'Under Review': 'investigating',
  Confirmed: 'confirmed_threat',
  'False Positive': 'false_positive',
  Closed: 'resolved',
};

const TRANSITIONS: Record<InvestigationStatus, InvestigationStatus[]> = {
  New: ['Under Review', 'False Positive', 'Closed'],
  'Under Review': ['New', 'Confirmed', 'False Positive', 'Closed'],
  Confirmed: ['Under Review', 'Closed'],
  'False Positive': ['Under Review', 'Closed'],
  Closed: ['Under Review'],
};

export function investigationStatus(finding: Finding): InvestigationStatus {
  return finding.investigationStatus || LEGACY_TO_STATUS[finding.status];
}

export function transitionFinding(
  finding: Finding,
  next: InvestigationStatus,
  actor: string,
  note: string,
  now = new Date().toISOString(),
): Finding {
  const previous = investigationStatus(finding);
  if (!TRANSITIONS[previous].includes(next)) {
    throw new Error(`Invalid status transition: ${previous} -> ${next}`);
  }
  if (!note.trim()) throw new Error('A reason is required for investigation actions.');
  const entry: InvestigationHistoryEntry = {
    timestamp: now,
    actor,
    action: next === 'Under Review' && previous === 'Closed' ? 'Reopened' : `Status changed to ${next}`,
    fromStatus: previous,
    toStatus: next,
    note: note.trim(),
  };
  return {
    ...finding,
    status: STATUS_TO_LEGACY[next],
    investigationStatus: next,
    history: [...(finding.history || []), entry],
    notes: finding.notes || [],
  };
}

export function appendHistory(
  finding: Finding,
  actor: string,
  action: string,
  note: string,
  now = new Date().toISOString(),
): Finding {
  const status = investigationStatus(finding);
  return {
    ...finding,
    history: [
      ...(finding.history || []),
      { timestamp: now, actor, action, fromStatus: status, toStatus: status, note },
    ],
  };
}

export function detectionAlertKey(finding: Finding): string {
  return [
    finding.platform.toLowerCase(),
    finding.identifier.trim().toLowerCase().replace(/^@/, ''),
    finding.matchedOfficialAsset?.id || finding.brandId,
  ].join('|');
}

export function alertForFinding(
  finding: Finding,
  alerts: Array<{ stableKey: string; severity: RiskLevel }>,
  id: string,
  now = new Date().toISOString(),
) {
  if (finding.riskScore < HIGH_THRESHOLD || finding.isOfficialAsset) return null;
  const stableKey = detectionAlertKey(finding);
  const prior = alerts.filter((alert) => alert.stableKey === stableKey);
  const severity = severityForScore(finding.riskScore);
  const rank: Record<RiskLevel, number> = {
    informational: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };
  if (prior.length && !prior.some((alert) => rank[severity] > rank[alert.severity])) return null;
  return {
    id,
    stableKey,
    detectionId: finding.id,
    score: finding.riskScore,
    severity,
    createdAt: now,
    read: false,
    escalated: prior.length > 0,
  };
}
