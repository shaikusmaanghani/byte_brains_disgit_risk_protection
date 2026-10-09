import React from 'react';
import {
  ShieldAlert,
  Smartphone,
  Share2,
  AlertTriangle,
  CheckCircle2,
  Clock,
  TrendingUp,
  ArrowUpRight,
  ExternalLink,
  ChevronRight,
  Layers,
  Radio,
  FileSearch,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { Finding, BrandProfile } from '../types';
import { RadarChart } from '../components/RadarChart';

interface DashboardProps {
  overview: any;
  trends: any;
  findings: Finding[];
  brand: BrandProfile;
  onSelectFinding: (finding: Finding) => void;
  onNavigateToScan: () => void;
  onNavigateToThreats: () => void;
  onRunScan: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  overview,
  trends,
  findings,
  brand,
  onSelectFinding,
  onNavigateToScan,
  onNavigateToThreats,
  onRunScan,
}) => {
  const topCriticalThreat = findings.find((f) => f.riskLevel === 'critical') || findings[0];

  const threatLevelColors = {
    Critical: 'from-rose-950/60 via-slate-900 to-slate-900 border-rose-500/40 text-rose-400',
    High: 'from-orange-950/60 via-slate-900 to-slate-900 border-orange-500/40 text-orange-400',
    Medium: 'from-amber-950/60 via-slate-900 to-slate-900 border-amber-500/40 text-amber-400',
    Low: 'from-cyan-950/60 via-slate-900 to-slate-900 border-cyan-500/40 text-cyan-400',
    Informational: 'from-emerald-950/60 via-slate-900 to-slate-900 border-emerald-500/40 text-emerald-400',
  };

  const currentLevel = overview?.overallThreatLevel || 'High';

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Prominent Global Threat Level Banner */}
      <div
        className={`p-5 rounded-2xl border bg-gradient-to-r ${threatLevelColors[currentLevel as keyof typeof threatLevelColors]} shadow-lg relative overflow-hidden`}
      >
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
              <span className="text-[11px] font-mono uppercase tracking-widest font-semibold text-slate-400">
                Active Cyber Threat Condition
              </span>
            </div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
                <span>Threat Level:</span>
                <span className="uppercase text-rose-400">{currentLevel}</span>
              </h1>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-900/80 border border-slate-700 text-slate-300">
                {overview?.activeThreats || 0} active incidents
              </span>
            </div>
            <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
              Targeted brand spoofing detected against <strong className="text-white">{brand.name}</strong> on Google Play Store and X/Twitter. Multiple rogue app publishers mimicking banking credentials with publisher mismatch.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={onNavigateToScan}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-colors flex items-center gap-1.5"
            >
              <FileSearch className="w-3.5 h-3.5 text-cyan-400" />
              <span>Manual Twin Scanner</span>
            </button>
            <button
              onClick={onRunScan}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold transition-colors shadow-md shadow-cyan-500/20"
            >
              Run Surface Scan
            </button>
          </div>
        </div>
      </div>

      {/* Primary KPI Grid (Zero-Pill, high-contrast tabular typography) */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider block">Monitored Assets</span>
          <span className="font-mono text-xl font-bold text-white tabular-nums">
            {overview?.totalMonitoredAssets || 0}
          </span>
          <span className="text-[10px] text-slate-500 block mt-0.5">
            {overview?.applicationsMonitored || 0} Apps · {overview?.socialAssetsMonitored || 0} Handles
          </span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-rose-400 uppercase tracking-wider block">Critical Threats</span>
          <span className="font-mono text-xl font-bold text-rose-400 tabular-nums">
            {overview?.criticalThreats || 0}
          </span>
          <span className="text-[10px] text-rose-400/80 block mt-0.5">Immediate takedown queue</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-orange-400 uppercase tracking-wider block">High-Risk Threats</span>
          <span className="font-mono text-xl font-bold text-orange-400 tabular-nums">
            {overview?.highRiskThreats || 0}
          </span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Requires analyst review</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-amber-400 uppercase tracking-wider block">Medium-Risk</span>
          <span className="font-mono text-xl font-bold text-amber-400 tabular-nums">
            {overview?.mediumRiskThreats || 0}
          </span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Suspicious overlap</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-cyan-400 uppercase tracking-wider block">Last 24 Hours</span>
          <span className="font-mono text-xl font-bold text-cyan-400 tabular-nums">
            +{overview?.detectedLast24h || 0}
          </span>
          <span className="text-[10px] text-slate-500 block mt-0.5">+{overview?.detectedLast7d || 0} past 7 days</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-emerald-400 uppercase tracking-wider block">Resolved Threats</span>
          <span className="font-mono text-xl font-bold text-emerald-400 tabular-nums">
            {overview?.resolvedThreats || 0}
          </span>
          <span className="text-[10px] text-emerald-400/80 block mt-0.5">Confirmed neutralised</span>
        </div>
      </div>

      {/* Two Column Layout: Impersonation Radar Showcase + Trends Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Flagship Impersonation Radar Highlight */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-start justify-between border-b border-slate-800/80 pb-3">
            <div>
              <span className="text-[10px] font-mono uppercase tracking-wider text-rose-400 font-bold">
                HIGH PRIORITY INVESTIGATION
              </span>
              <h3 className="text-sm font-bold text-white mt-0.5">
                {topCriticalThreat?.candidateName || 'Acme Mobile Banking'}
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                Publisher: {topCriticalThreat?.publisherOrDeveloper || 'Rogue Apps LLC'}
              </p>
            </div>
            {topCriticalThreat && (
              <button
                onClick={() => onSelectFinding(topCriticalThreat)}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
              >
                <span>Inspect</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {topCriticalThreat && (
            <div className="py-2 flex justify-center">
              <RadarChart
                score={topCriticalThreat.riskScore}
                riskLevel={topCriticalThreat.riskLevel}
                breakdown={topCriticalThreat.radarBreakdown}
                size={230}
              />
            </div>
          )}

          <div className="bg-slate-950/80 rounded-lg p-3 border border-slate-800 text-[11px] text-slate-300 space-y-1">
            <span className="font-bold text-rose-400 block">Why this was flagged:</span>
            <p className="line-clamp-2">
              {topCriticalThreat?.summaryExplanation ||
                'Candidate replicates registered banking application name while distributed by unauthorized publisher.'}
            </p>
          </div>
        </div>

        {/* Time Series Analytics (Area Chart) */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white">Threat Volume Over Time</h3>
              <p className="text-xs text-slate-400">
                Discovered mobile apps vs social media impersonations (Past 7 Days)
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
                <span className="text-slate-300">App Threats</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-indigo-500" />
                <span className="text-slate-300">Social Threats</span>
              </div>
            </div>
          </div>

          <div className="h-64 w-full pt-4">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends?.threatsOverTime || []}>
                <defs>
                  <linearGradient id="colorApp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorSoc" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#020617',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="appThreats"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorApp)"
                  name="App Store"
                />
                <Area
                  type="monotone"
                  dataKey="socialThreats"
                  stroke="#6366f1"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorSoc)"
                  name="Social Media"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="text-[11px] text-slate-500 flex justify-between border-t border-slate-800/80 pt-2 font-mono">
            <span>Automated Daily Crawler Cadence</span>
            <span className="text-cyan-400">7 Connected Surface Pipelines</span>
          </div>
        </div>
      </div>

      {/* Active Threat Findings Stream */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-md">
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between bg-slate-950/40">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span>Active Threat Intelligence Stream</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Live Detections
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Evaluated by multi-vector scoring (Homoglyph, Levenshtein distance, Publisher mismatch)
            </p>
          </div>

          <button
            onClick={onNavigateToThreats}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
          >
            <span>View All ({findings.length})</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-2.5">Candidate Asset</th>
                <th className="px-4 py-2.5">Platform</th>
                <th className="px-4 py-2.5">Publisher / Handle</th>
                <th className="px-4 py-2.5">Risk Score</th>
                <th className="px-4 py-2.5">Key Threat Vector</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {findings.slice(0, 6).map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => onSelectFinding(finding)}
                  className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3">
                    <div className="font-semibold text-white">{finding.candidateName}</div>
                    <div className="text-[11px] font-mono text-slate-400">{finding.identifier}</div>
                  </td>

                  <td className="px-4 py-3 text-slate-300 capitalize font-mono text-[11px]">
                    {finding.platform.replace(/_/g, ' ')}
                  </td>

                  <td className="px-4 py-3 text-slate-300 font-mono text-[11px]">
                    {finding.publisherOrDeveloper || '—'}
                  </td>

                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5 font-mono">
                      <span
                        className={`font-bold tabular-nums ${
                          finding.riskScore >= 80
                            ? 'text-rose-400'
                            : finding.riskScore >= 60
                            ? 'text-orange-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {finding.riskScore}
                      </span>
                      <span className="text-[10px] text-slate-400 uppercase">
                        [{finding.riskLevel}]
                      </span>
                    </div>
                  </td>

                  <td className="px-4 py-3 text-slate-300 max-w-xs truncate text-[11px]">
                    {finding.signals[0]?.explanation || 'Suspicious name similarity'}
                  </td>

                  <td className="px-4 py-3">
                    <span
                      className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                        finding.status === 'confirmed_threat'
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                          : finding.status === 'investigating'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          : finding.status === 'resolved'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                      }`}
                    >
                      {finding.status.replace(/_/g, ' ')}
                    </span>
                  </td>

                  <td className="px-4 py-3 text-right">
                    <button className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold">
                      Investigate →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
