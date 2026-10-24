import type { Finding, InvestigationStatus } from '../types/index.js';
import { investigationStatus } from './investigation.js';
import { draftTakedownReport } from './takedownReport.js';

export function listTopRisks(findings: Finding[], count = 5): Finding[] {
  return [...findings]
    .filter((finding) => !finding.isOfficialAsset)
    .sort((a, b) => b.riskScore - a.riskScore || new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime())
    .slice(0, Math.max(1, Math.min(20, count)));
}

export function filterByStatus(findings: Finding[], status: InvestigationStatus): Finding[] {
  return findings.filter((finding) => investigationStatus(finding) === status);
}

export function explainScore(finding: Finding): string {
  const details = (finding.signals || []).map((signal) =>
    `- ${signal.type}: ${signal.score} points. ${signal.explanation}`,
  );
  return `Detection ${finding.id} is scored ${finding.riskScore}/100 (${finding.riskLevel}).\n${details.join('\n') || 'No scoring evidence was recorded.'}`;
}

export function historyOf(finding: Finding, actorQuery?: string): string {
  let entries = finding.history || [];
  if (actorQuery) {
    const actor = actorQuery.toLowerCase().replace(/\s+/g, '');
    const expected = actor.includes('analyst1')
      ? 'analystone'
      : actor.includes('analyst2')
        ? 'analysttwo'
        : actor.includes('admin')
          ? 'marcusvance'
          : actor;
    entries = entries.filter((entry) => entry.actor.toLowerCase().replace(/\s+/g, '') === expected);
  }
  return entries.length
    ? entries.map((entry) => `- ${entry.timestamp}: ${entry.actor} — ${entry.action}${entry.note ? ` (${entry.note})` : ''}`).join('\n')
    : actorQuery
      ? `I don't have data on that for ${actorQuery} on ${finding.id}.`
      : `Detection ${finding.id} has no recorded investigation history.`;
}

export function summarizeQueue(findings: Finding[]): string {
  const open = findings.filter((finding) => !['Closed', 'False Positive'].includes(investigationStatus(finding)));
  const highRisk = open.filter((finding) => finding.riskScore >= 75).length;
  return `Queue contains ${findings.length} detections: ${open.length} open, ${highRisk} open high-risk, ${findings.filter((f) => investigationStatus(f) === 'Confirmed').length} confirmed, ${findings.filter((f) => investigationStatus(f) === 'False Positive').length} false positives, and ${findings.filter((f) => investigationStatus(f) === 'Closed').length} closed.`;
}

export function getDetection(findings: Finding[], query: string): Finding | undefined {
  const tokens: string[] = query.toLowerCase().match(/[a-z0-9_.-]+/g) || [];
  const exact = findings.find((finding) => tokens.includes(finding.id.toLowerCase()));
  if (exact) return exact;
  const id = query.match(/#\s*(\d+)|\b(?:detection|finding)\s*(?:number\s*)?(\d+)\b/i);
  const numeric = Number(id?.[1] || id?.[2]);
  if (!Number.isInteger(numeric) || numeric < 1) return undefined;
  return listTopRisks(findings, findings.length)[numeric - 1];
}

export function draftTakedown(findings: Finding[], query: string, actor: string): string {
  const finding = getDetection(findings, query);
  if (!finding) return "I don't have data on that.";
  return draftTakedownReport(finding, actor);
}

export function answerAnalystQuestion(query: string, findings: Finding[], actor: string): string {
  const lower = query.toLowerCase();
  if (/top|highest|priority/.test(lower)) {
    const count = Number(lower.match(/\b(\d{1,2})\b/)?.[1] || 5);
    const risks = listTopRisks(findings, count);
    return risks.length
      ? risks.map((finding, index) => `${index + 1}. ${finding.id}: ${finding.candidateName} — ${finding.riskScore}/100 (${finding.riskLevel})`).join('\n')
      : "I don't have data on that.";
  }
  if (/summary|summari[sz]e|queue|how many/.test(lower)) return summarizeQueue(findings);
  if (/status/.test(lower)) {
    const statusMatch = lower.match(/new|under review|confirmed|false positive|closed/i)?.[0];
    if (!statusMatch) return "I don't have data on that.";
    const status = statusMatch.toLowerCase() === 'under review'
      ? 'Under Review'
      : statusMatch.replace(/\b\w/g, (letter) => letter.toUpperCase()) as InvestigationStatus;
    const matches = filterByStatus(findings, status);
    return matches.length
      ? matches.map((finding) => `${finding.id}: ${finding.candidateName} (${finding.riskScore}/100)`).join('\n')
      : `No detections currently have status ${status}.`;
  }
  const finding = getDetection(findings, query);
  if (!finding) return "I don't have data on that.";
  if (/history|what did|who|analyst/.test(lower)) {
    const actorQuery = lower.match(/analyst\s*[12]|analyst[12]|admin/)?.[0];
    return `History for ${finding.id}:\n${historyOf(finding, actorQuery)}`;
  }
  if (/why|score|explain/.test(lower)) return explainScore(finding);
  if (/draft|takedown/.test(lower)) {
    try {
      return draftTakedown(findings, query, actor);
    } catch (error) {
      return error instanceof Error ? error.message : "I don't have data on that.";
    }
  }
  return "I don't have data on that.";
}

export const list_top_risks = listTopRisks;
export const get_detection = getDetection;
export const explain_score = explainScore;
export const filter_by_status = filterByStatus;
export const history_of = historyOf;
export const summarize_queue = summarizeQueue;
export const draft_takedown = draftTakedown;
