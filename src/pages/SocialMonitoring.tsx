import React from 'react';
import {
  Share2,
  ShieldAlert,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  MessageSquare,
  UserCheck,
} from 'lucide-react';
import { Finding } from '../types';

interface SocialMonitoringProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onNavigateToScan: () => void;
}

export const SocialMonitoring: React.FC<SocialMonitoringProps> = ({
  findings,
  onSelectFinding,
  onNavigateToScan,
}) => {
  const socialFindings = findings.filter((f) => f.assetType === 'social_profile');
  const xCount = socialFindings.filter((f) => f.platform === 'x_twitter').length;
  const igCount = socialFindings.filter((f) => f.platform === 'instagram').length;
  const criticalCount = socialFindings.filter((f) => f.riskLevel === 'critical').length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Share2 className="w-5 h-5 text-sky-400" />
            <span>Social Network Impersonation Defense</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Surveillance of X/Twitter, Instagram, LinkedIn, and Facebook for fraudulent customer support channels, homoglyphs, and phishing lures.
          </p>
        </div>

        <button
          onClick={onNavigateToScan}
          className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors"
        >
          <span>Scan Suspect Social Handle</span>
        </button>
      </div>

      {/* Surface Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider block">Social Spoofs Tracked</span>
          <span className="font-mono text-2xl font-bold text-white tabular-nums">{socialFindings.length}</span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Discovered handles</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-rose-400 uppercase tracking-wider block">Critical Social Lures</span>
          <span className="font-mono text-2xl font-bold text-rose-400 tabular-nums">{criticalCount}</span>
          <span className="text-[10px] text-rose-400/80 block mt-0.5">Urgent support / fake refund</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-sky-400 uppercase tracking-wider block">X / Twitter Targets</span>
          <span className="font-mono text-2xl font-bold text-sky-400 tabular-nums">{xCount}</span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Homoglyph & typo handles</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-pink-400 uppercase tracking-wider block">Instagram Targets</span>
          <span className="font-mono text-2xl font-bold text-pink-400 tabular-nums">{igCount}</span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Unauthorized giveaway pages</span>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-400">
          Active Social Impersonation Leads
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {socialFindings.map((finding) => (
            <div
              key={finding.id}
              onClick={() => onSelectFinding(finding)}
              className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all space-y-4 shadow-md group"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 capitalize">
                      {finding.platform.replace(/_/g, ' ')}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold border ${
                        finding.riskLevel === 'critical'
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                          : 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                      }`}
                    >
                      Risk: {finding.riskScore}/100 [{finding.riskLevel}]
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
                    {finding.candidateName}
                  </h3>
                </div>

                <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 transition-colors" />
              </div>

              <div className="bg-slate-950/80 rounded-lg p-3 border border-slate-800/80 text-xs space-y-1 font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Suspect Handle:</span>
                  <span className="text-rose-400 font-bold">{finding.identifier}</span>
                </div>
              </div>

              <div className="space-y-1 text-xs text-slate-300">
                <span className="text-[10px] uppercase font-bold text-slate-400 font-mono">Bio Lure Snippet:</span>
                <p className="line-clamp-2 text-[11px] leading-relaxed bg-slate-950/40 p-2 rounded border border-slate-800">
                  {finding.descriptionSnippet || 'No bio snippet recorded.'}
                </p>
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800 font-mono">
                <span>Observed: {new Date(finding.lastSeen).toLocaleDateString()}</span>
                <span className="text-cyan-400 font-semibold group-hover:underline">Inspect Profile →</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
