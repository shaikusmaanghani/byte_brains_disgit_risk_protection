import React, { useState } from 'react';
import {
  ShieldAlert,
  X,
  CheckCircle2,
  AlertTriangle,
  Clock,
  User,
  ArrowRight,
  ExternalLink,
  Download,
  Send,
  Flag,
  FileCheck,
  Ban,
  ShieldCheck,
} from 'lucide-react';
import { Finding, FindingStatus, OfficialApp } from '../types';
import { RadarChart } from './RadarChart';

interface ThreatDetailModalProps {
  finding: Finding;
  onClose: () => void;
  onUpdateStatus: (id: string, status: FindingStatus, reason?: string) => Promise<void>;
  onAddNote: (id: string, noteContent: string, actionTaken?: string) => void;
  onAssignAnalyst: (id: string, analystName: string) => void;
  onDraftReport: (id: string) => Promise<string>;
}

export const ThreatDetailModal: React.FC<ThreatDetailModalProps> = ({
  finding,
  onClose,
  onUpdateStatus,
  onAddNote,
  onAssignAnalyst,
  onDraftReport,
}) => {
  const [newNote, setNewNote] = useState('');
  const [statusReason, setStatusReason] = useState('');
  const [actionError, setActionError] = useState('');
  const [reportText, setReportText] = useState('');
  const [reportError, setReportError] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<FindingStatus>(finding.status);
  const [analystName, setAnalystName] = useState(finding.assignedAnalyst || 'Sarah Chen');

  const statusOptions: { value: FindingStatus; label: string; color: string }[] = [
    { value: 'new', label: 'New', color: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
    { value: 'investigating', label: 'Investigating', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
    { value: 'confirmed_threat', label: 'Confirmed Threat', color: 'bg-rose-500/10 text-rose-400 border-rose-500/30' },
    { value: 'false_positive', label: 'False Positive', color: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
    { value: 'resolved', label: 'Resolved', color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
    { value: 'dismissed', label: 'Dismissed', color: 'bg-slate-700/30 text-slate-400 border-slate-700/50' },
  ];

  const handleStatusChange = async (status: FindingStatus) => {
    if (!statusReason.trim()) {
      setActionError('Enter a reason before recording an investigation action.');
      return;
    }
    setSelectedStatus(status);
    setActionError('');
    try {
      await onUpdateStatus(finding.id, status, statusReason.trim());
      setStatusReason('');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not update investigation status.');
    }
  };

  const draftReport = async () => {
    try {
      setReportError('');
      setReportText(await onDraftReport(finding.id));
    } catch (error) {
      setReportError(error instanceof Error ? error.message : 'Could not draft takedown report.');
    }
  };

  const downloadReport = (extension: 'md' | 'txt') => {
    const url = URL.createObjectURL(new Blob([reportText], { type: 'text/plain' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `${finding.id}-takedown.${extension}`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleAddNoteSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    onAddNote(finding.id, newNote.trim(), `Analyst updated finding`);
    setNewNote('');
  };

  const matchedApp = finding.matchedOfficialAsset as OfficialApp | undefined;
  const isApp = finding.assetType === 'mobile_application';
  const officialDetails = finding.officialAssetDetails;
  const matchingWords = new Set(
    (officialDetails?.description || '')
      .toLowerCase()
      .match(/[a-z0-9]{4,}/g) || [],
  );
  const renderHighlightedDescription = (text: string) => text.split(/(\b[a-z0-9]{4,}\b)/gi).map((part, index) =>
    matchingWords.has(part.toLowerCase())
      ? <mark key={`${part}-${index}`} className="rounded bg-amber-400/20 text-amber-100">{part}</mark>
      : part,
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-950/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-5xl max-h-[92vh] flex flex-col shadow-2xl shadow-black/80 overflow-hidden my-auto animate-in fade-in zoom-in-95 duration-200">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 bg-slate-950/80 flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {finding.id}
              </span>
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                {finding.assetType.replace(/_/g, ' ')} · {finding.platform.replace(/_/g, ' ')}
              </span>
              {finding.isSimulated && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
                  SIMULATED THREAT RECORD
                </span>
              )}
            </div>

            <h2 className="text-xl font-bold text-white flex items-center gap-3">
              <span>{finding.candidateName}</span>
              <span
                className={`text-xs px-2.5 py-0.5 rounded font-mono font-bold uppercase tracking-wider border ${
                  finding.riskLevel === 'critical'
                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                    : finding.riskLevel === 'high'
                    ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                    : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                }`}
              >
                Risk: {finding.riskScore}/100 [{finding.riskLevel}]
              </span>
            </h2>

            <div className="text-xs text-slate-400 flex items-center gap-4 pt-1">
              <span>First detected: {new Date(finding.firstSeen).toLocaleString()}</span>
              <span>·</span>
              <span>Last observed: {new Date(finding.lastSeen).toLocaleString()}</span>
              <span>·</span>
              <span>Confidence: {Math.round(finding.confidence * 100)}%</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(finding, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `sentinel_${finding.id}.json`;
                a.click();
              }}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Export finding as JSON"
            >
              <Download className="w-4 h-4" />
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Status Progression Bar */}
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Analyst Incident Status
              </div>
              <div className="flex flex-wrap gap-2">
                {statusOptions.map((st) => (
                  <button
                    key={st.value}
                    onClick={() => handleStatusChange(st.value)}
                    className={`px-3 py-1 rounded-lg text-xs font-semibold border transition-all ${
                      selectedStatus === st.value
                        ? `${st.color} shadow-sm ring-1 ring-current`
                        : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    {st.label}
                  </button>
                ))}
              </div>
              <label className="block mt-3 text-[11px] text-slate-400">
                Action reason (required)
                <input
                  value={statusReason}
                  onChange={(event) => setStatusReason(event.target.value)}
                  className="mt-1 block w-full min-w-64 rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                  placeholder="Record the evidence or rationale for this action"
                />
              </label>
              {actionError && <p role="alert" className="text-[11px] text-rose-300 mt-2">{actionError}</p>}
            </div>

            <div className="flex items-center gap-3">
              <div>
                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                  Assigned Analyst
                </div>
                <input
                  type="text"
                  value={analystName}
                  onChange={(e) => {
                    setAnalystName(e.target.value);
                    onAssignAnalyst(finding.id, e.target.value);
                  }}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-white focus:outline-none focus:border-cyan-500 font-medium"
                />
              </div>
            </div>
          </div>

          {/* Side by Side Diff: Candidate vs Official */}
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center justify-between">
              <span>Candidate vs Registered Official Brand Identity</span>
              <span className="text-[11px] text-cyan-400 lowercase font-mono">Discrepancy Inspector</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Candidate Box */}
              <div className="bg-rose-950/20 border border-rose-500/30 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-rose-500/20 pb-2">
                  <span className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Candidate (Discovered Asset)</span>
                  </span>
                  <a
                    href={finding.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[11px] text-rose-300 hover:underline flex items-center gap-1"
                  >
                    <span>Inspect Target</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>

                <div className="space-y-2 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Asset Name:</span>
                    <span className="font-semibold text-white font-mono">{finding.candidateName}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Publisher / Developer:</span>
                    <span className="font-semibold text-rose-300 font-mono">
                      {finding.publisherOrDeveloper || 'Unknown / Unverified'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Identifier / Package ID:</span>
                    <span className="font-semibold text-rose-300 font-mono">{finding.identifier}</span>
                  </div>
                  {finding.candidatePayload?.website && (
                    <div>
                      <span className="text-slate-400 block text-[11px]">Support / Target Website:</span>
                      <span className="font-semibold text-rose-300 font-mono">
                        {finding.candidatePayload.website}
                      </span>
                    </div>
                  )}
                  {finding.descriptionSnippet && (
                    <div>
                      <span className="text-slate-400 block text-[11px]">Description Snippet:</span>
                      <p className="text-slate-300 bg-slate-950/60 p-2 rounded border border-rose-500/20 text-[11px] leading-relaxed">
                        {renderHighlightedDescription(finding.descriptionSnippet)}
                      </p>
                    </div>
                  )}
                  {finding.iconUrl && <img src={finding.iconUrl} alt={`${finding.candidateName} logo`} className="h-12 w-12 rounded border border-slate-700 object-cover" />}
                </div>
              </div>

              {/* Official Registered Box */}
              <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-emerald-500/20 pb-2">
                  <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Official (Authorized Identity)</span>
                  </span>
                  <span className="text-[11px] text-emerald-400 font-mono">Verified Whitelist</span>
                </div>

                <div className="space-y-2 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Official App / Brand Name:</span>
                    <span className="font-semibold text-white font-mono">
                      {officialDetails?.name || (matchedApp ? matchedApp.appName : 'Acme Financial')}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Authorized Publisher:</span>
                    <span className="font-semibold text-emerald-300 font-mono">
                      {officialDetails?.publisherOrDeveloper || matchedApp?.publisher || 'Not registered'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Legitimate Package ID:</span>
                    <span className="font-semibold text-emerald-300 font-mono">
                      {matchedApp ? matchedApp.packageId : 'com.acme.mobilebanking'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Authorized Domains:</span>
                    <span className="font-semibold text-emerald-300 font-mono">
                      acmefinancial.com, acmebank.com
                    </span>
                  </div>
                  {officialDetails?.logoRef && <img src={officialDetails.logoRef} alt="Official brand logo" className="h-12 w-12 rounded border border-emerald-700 object-cover" />}
                  {officialDetails?.description && (
                    <div>
                      <span className="text-slate-400 block text-[11px]">Registered description:</span>
                      <p className="text-slate-300 bg-slate-950/60 p-2 rounded border border-emerald-500/20 text-[11px] leading-relaxed">
                        {officialDetails.description}
                      </p>
                    </div>
                  )}
                  <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-500/20 text-[11px] text-emerald-200">
                    <div className="font-semibold">Security Policy Verification:</div>
                    Publisher credentials are cryptographic prerequisites. Discrepancies represent unauthorized code distribution.
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Why Was This Flagged? Evidence Cards & Impersonation Radar */}
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
              Why was this flagged? — Algorithmic Detection Signals & Evidence
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Radar visualization */}
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 flex flex-col items-center justify-center">
                <div className="text-xs font-semibold text-slate-300 mb-2">Impersonation Radar</div>
                <RadarChart
                  score={finding.riskScore}
                  riskLevel={finding.riskLevel}
                  breakdown={finding.radarBreakdown}
                  size={240}
                />
              </div>

              {/* Structured Signals List */}
              <div className="lg:col-span-2 space-y-2.5">
                {finding.signals.map((signal, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold font-mono text-cyan-400 uppercase">
                          {signal.type.replace(/_/g, ' ')}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          +{signal.pointsContributed ?? signal.score} pts (wt: {signal.weight})
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed">{signal.explanation}</p>
                      {signal.highlightDetails && (
                        <div className="text-[11px] font-mono text-slate-400 mt-1 flex flex-wrap gap-2">
                          {signal.highlightDetails.candidateValue && (
                            <span className="text-rose-400">
                              Candidate: "{signal.highlightDetails.candidateValue}"
                            </span>
                          )}
                          {signal.highlightDetails.officialValue && (
                            <span className="text-emerald-400">
                              Official: "{signal.highlightDetails.officialValue}"
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                ))}

                <div className="p-3.5 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-xs text-cyan-200">
                  <span className="font-bold">Recommended Analyst Action: </span>
                  <span>{finding.recommendedAction}</span>
                </div>
              </div>
            </div>
          </div>

          <section className="rounded-xl border border-slate-800 bg-slate-950/40 p-4">
            <h3 className="text-xs font-bold uppercase tracking-wide text-slate-300 mb-3">Investigation history</h3>
            {(finding.history || []).length ? (
              <ol className="space-y-3 border-l border-slate-700 ml-1 pl-4">
                {(finding.history || []).map((entry, index) => (
                  <li key={`${entry.timestamp}-${index}`} className="relative text-xs">
                    <span className="absolute -left-[21px] top-1 w-2 h-2 rounded-full bg-cyan-400" />
                    <div className="text-slate-300 font-semibold">{entry.action} · {entry.actor}</div>
                    <div className="text-[10px] text-slate-500">{new Date(entry.timestamp).toLocaleString()}</div>
                    {entry.note && <p className="mt-1 text-slate-400">{entry.note}</p>}
                  </li>
                ))}
              </ol>
            ) : <p className="text-xs text-slate-500">No audit events recorded yet.</p>}
          </section>

          {(finding.investigationStatus === 'Confirmed' || finding.status === 'confirmed_threat') && (
            <section className="rounded-xl border border-cyan-700/50 bg-slate-950/40 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wide text-cyan-200">Takedown report draft</h3>
                <button onClick={draftReport} className="px-3 py-1.5 rounded bg-cyan-700 hover:bg-cyan-600 text-xs font-semibold text-white">Generate draft</button>
              </div>
              {reportError && <p role="alert" className="text-xs text-rose-300">{reportError}</p>}
              {reportText && (
                <>
                  <textarea value={reportText} onChange={(event) => setReportText(event.target.value)} rows={12} className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs text-slate-200 font-mono" aria-label="Editable takedown report" />
                  <div className="flex flex-wrap gap-2">
                    <button onClick={() => navigator.clipboard.writeText(reportText)} className="px-3 py-1.5 rounded bg-slate-800 text-xs text-slate-200">Copy</button>
                    <button onClick={() => downloadReport('md')} className="px-3 py-1.5 rounded bg-slate-800 text-xs text-slate-200">Export .md</button>
                    <button onClick={() => downloadReport('txt')} className="px-3 py-1.5 rounded bg-slate-800 text-xs text-slate-200">Export .txt</button>
                    <button onClick={() => window.print()} className="px-3 py-1.5 rounded bg-slate-800 text-xs text-slate-200">Print / PDF</button>
                  </div>
                </>
              )}
            </section>
          )}

          {/* Investigation Notes & Timeline */}
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
              Investigation Notes & SOC Audit Trail
            </div>

            <div className="space-y-3 mb-4">
              {finding.notes.length === 0 ? (
                <div className="text-xs text-slate-500 italic p-3 bg-slate-950/40 rounded-lg border border-slate-800/80">
                  No notes recorded yet. Add an analyst observation below.
                </div>
              ) : (
                finding.notes.map((note) => (
                  <div
                    key={note.id}
                    className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="font-semibold text-slate-300">{note.authorName}</span>
                      <span>{new Date(note.createdAt).toLocaleString()}</span>
                    </div>
                    <p className="text-slate-200">{note.content}</p>
                    {note.actionTaken && (
                      <div className="text-[10px] text-cyan-400 font-mono">Action: {note.actionTaken}</div>
                    )}
                  </div>
                ))
              )}
            </div>

            <form onSubmit={handleAddNoteSubmit} className="flex gap-2">
              <input
                type="text"
                placeholder="Log analyst observation or takedown tracking ID..."
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                disabled={!newNote.trim()}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors"
              >
                <span>Add Note</span>
                <Send className="w-3.5 h-3.5" />
              </button>
            </form>
          </div>
        </div>

        {/* Modal Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
          <div className="text-xs text-slate-400">
            Audit ID: <span className="font-mono text-slate-300">{finding.id}</span>
          </div>

          <div className="flex items-center gap-2">
            {selectedStatus === 'new' && (
              <button
                onClick={() => handleStatusChange('investigating')}
                className="px-3.5 py-1.5 rounded-lg bg-amber-500/10 text-amber-300 border border-amber-500/30 text-xs font-semibold"
              >
                Start Review
              </button>
            )}
            <button
              onClick={() => handleStatusChange('confirmed_threat')}
              className="px-3.5 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-semibold flex items-center gap-1.5 transition-colors"
            >
              <Flag className="w-3.5 h-3.5" />
              <span>Confirm Threat</span>
            </button>
            <button
              onClick={() => handleStatusChange('false_positive')}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition-colors"
            >
              <Ban className="w-3.5 h-3.5" />
              <span>Mark False Positive</span>
            </button>
            <button
              onClick={() => handleStatusChange('resolved')}
              className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-bold flex items-center gap-1.5 transition-colors"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Mark Resolved</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
