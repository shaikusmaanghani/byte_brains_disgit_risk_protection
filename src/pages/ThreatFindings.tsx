import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Download,
  ExternalLink,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Plus,
} from 'lucide-react';
import { Finding, PlatformType, RiskLevel, FindingStatus, AssetType } from '../types';

interface ThreatFindingsProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onRefresh: () => void;
  onNavigateToScan: () => void;
}

export const ThreatFindings: React.FC<ThreatFindingsProps> = ({
  findings,
  onSelectFinding,
  onRefresh,
  onNavigateToScan,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [platformFilter, setPlatformFilter] = useState<string>('all');
  const [assetTypeFilter, setAssetTypeFilter] = useState<string>('all');
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'risk_desc' | 'risk_asc' | 'newest' | 'oldest'>('risk_desc');

  // Client-side filtering & sorting
  const filtered = findings.filter((f) => {
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const matchName = f.candidateName.toLowerCase().includes(q);
      const matchId = f.identifier.toLowerCase().includes(q);
      const matchPub = (f.publisherOrDeveloper || '').toLowerCase().includes(q);
      const matchDesc = (f.descriptionSnippet || '').toLowerCase().includes(q);
      if (!matchName && !matchId && !matchPub && !matchDesc) return false;
    }
    if (platformFilter !== 'all' && f.platform !== platformFilter) return false;
    if (assetTypeFilter !== 'all' && f.assetType !== assetTypeFilter) return false;
    if (riskFilter !== 'all' && f.riskLevel !== riskFilter) return false;
    if (statusFilter !== 'all' && f.status !== statusFilter) return false;
    return true;
  });

  filtered.sort((a, b) => {
    if (sortBy === 'risk_desc') return b.riskScore - a.riskScore;
    if (sortBy === 'risk_asc') return a.riskScore - b.riskScore;
    if (sortBy === 'newest') return new Date(b.firstSeen).getTime() - new Date(a.firstSeen).getTime();
    if (sortBy === 'oldest') return new Date(a.firstSeen).getTime() - new Date(b.firstSeen).getTime();
    return 0;
  });

  const exportCSV = () => {
    const headers = ['ID', 'Asset Type', 'Platform', 'Candidate Name', 'Identifier', 'Publisher', 'Risk Score', 'Risk Level', 'Status', 'First Seen'];
    const rows = filtered.map((f) => [
      f.id,
      f.assetType,
      f.platform,
      `"${f.candidateName.replace(/"/g, '""')}"`,
      `"${f.identifier}"`,
      `"${(f.publisherOrDeveloper || '').replace(/"/g, '""')}"`,
      f.riskScore,
      f.riskLevel,
      f.status,
      f.firstSeen,
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel_findings_${Date.now()}.csv`;
    a.click();
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <span>Threat Findings Repository</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
              {filtered.length} Indexed Records
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Comprehensive surveillance ledger of discovered brand impersonations across app stores and social platforms.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={exportCSV}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={onNavigateToScan}
            className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold flex items-center gap-1.5 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Manual Scan</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search candidate name, package ID, handle, publisher, or keywords..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-medium"
            />
          </div>

          <div className="flex flex-wrap gap-2">
            {/* Platform Filter */}
            <select
              value={platformFilter}
              onChange={(e) => setPlatformFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 capitalize"
            >
              <option value="all">All Platforms</option>
              <option value="google_play">Google Play</option>
              <option value="apple_app_store">Apple App Store</option>
              <option value="x_twitter">X / Twitter</option>
              <option value="instagram">Instagram</option>
              <option value="linkedin">LinkedIn</option>
              <option value="facebook">Facebook</option>
            </select>

            {/* Asset Type */}
            <select
              value={assetTypeFilter}
              onChange={(e) => setAssetTypeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 capitalize"
            >
              <option value="all">All Asset Types</option>
              <option value="mobile_application">Mobile Applications</option>
              <option value="social_profile">Social Profiles</option>
            </select>

            {/* Risk Level */}
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 capitalize"
            >
              <option value="all">All Risk Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>

            {/* Status */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 capitalize"
            >
              <option value="all">All Statuses</option>
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="confirmed_threat">Confirmed Threat</option>
              <option value="false_positive">False Positive</option>
              <option value="resolved">Resolved</option>
              <option value="dismissed">Dismissed</option>
            </select>

            {/* Sort */}
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="risk_desc">Sort: Highest Risk</option>
              <option value="risk_asc">Sort: Lowest Risk</option>
              <option value="newest">Sort: Newest</option>
              <option value="oldest">Sort: Oldest</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Discovered Asset</th>
                <th className="px-4 py-3">Type & Platform</th>
                <th className="px-4 py-3">Publisher / Account</th>
                <th className="px-4 py-3">Risk Assessment</th>
                <th className="px-4 py-3">Signals Breakdown</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Analyst Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500 text-xs italic">
                    No threat findings matching active query filters.
                  </td>
                </tr>
              ) : (
                filtered.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => onSelectFinding(item)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3.5">
                      <div className="font-bold text-white text-xs">{item.candidateName}</div>
                      <div className="text-[11px] font-mono text-slate-400 mt-0.5">{item.identifier}</div>
                    </td>

                    <td className="px-4 py-3.5">
                      <div className="capitalize text-slate-200">
                        {item.assetType.replace(/_/g, ' ')}
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono capitalize">
                        {item.platform.replace(/_/g, ' ')}
                      </div>
                    </td>

                    <td className="px-4 py-3.5">
                      <div className="text-slate-200 font-mono text-[11px]">
                        {item.publisherOrDeveloper || '—'}
                      </div>
                      {item.isSimulated && (
                        <span className="text-[9px] font-mono text-amber-400 uppercase">
                          Simulated
                        </span>
                      )}
                    </td>

                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-1.5 font-mono">
                        <span
                          className={`font-black text-sm tabular-nums ${
                            item.riskScore >= 80
                              ? 'text-rose-400'
                              : item.riskScore >= 60
                              ? 'text-orange-400'
                              : item.riskScore >= 35
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {item.riskScore}
                        </span>
                        <span className="text-[10px] text-slate-400 font-semibold uppercase">
                          [{item.riskLevel}]
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-500 capitalize">
                        {item.classification.replace(/_/g, ' ')}
                      </div>
                    </td>

                    <td className="px-4 py-3.5 max-w-xs">
                      <div className="text-slate-300 truncate text-[11px]">
                        {item.signals[0]?.explanation || 'Name similarity'}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                        {item.signals.length} threat signal vectors detected
                      </div>
                    </td>

                    <td className="px-4 py-3.5">
                      <span
                        className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                          item.status === 'confirmed_threat'
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            : item.status === 'investigating'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : item.status === 'resolved'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                        }`}
                      >
                        {item.status.replace(/_/g, ' ')}
                      </span>
                    </td>

                    <td className="px-4 py-3.5 text-right">
                      <button className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-semibold text-[11px] transition-colors">
                        Deep Diff →
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
