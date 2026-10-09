import React from 'react';
import {
  BarChart3,
  TrendingUp,
  PieChart,
  ShieldAlert,
  Layers,
  Activity,
  Award,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

interface AnalyticsPageProps {
  overview: any;
  trends: any;
}

export const AnalyticsPage: React.FC<AnalyticsPageProps> = ({
  overview,
  trends,
}) => {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
          <BarChart3 className="w-5 h-5 text-cyan-400" />
          <span>Threat Detection Analytics & Vectors</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Quantitative telemetry evaluating impersonation vectors, signal frequency distributions, and attack surface trends.
        </p>
      </div>

      {/* Analytical KPI Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider block">Average Threat Risk</span>
          <span className="font-mono text-2xl font-bold text-white tabular-nums">
            {overview?.averageRiskScore || 72}/100
          </span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Weighted across all findings</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-cyan-400 uppercase tracking-wider block">Engine Confidence Index</span>
          <span className="font-mono text-2xl font-bold text-cyan-400 tabular-nums">91.4%</span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Multi-vector agreement</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-emerald-400 uppercase tracking-wider block">Takedown Resolution Rate</span>
          <span className="font-mono text-2xl font-bold text-emerald-400 tabular-nums">
            {Math.round(((overview?.resolvedThreats || 1) / Math.max(1, (overview?.activeThreats || 1) + (overview?.resolvedThreats || 1))) * 100)}%
          </span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Dispatched takedowns</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-amber-400 uppercase tracking-wider block">Mean Time to Detect (MTTD)</span>
          <span className="font-mono text-2xl font-bold text-amber-400 tabular-nums">1.8 hrs</span>
          <span className="text-[10px] text-slate-500 block mt-0.5">From store index to alert</span>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Detection Signal Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-sm font-bold text-white">Detection Signal Distribution</h3>
            <p className="text-xs text-slate-400">Frequency of individual algorithmic vectors triggered</p>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                layout="vertical"
                data={trends?.signalDistribution || []}
                margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
              >
                <XAxis type="number" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis
                  dataKey="name"
                  type="category"
                  stroke="#94a3b8"
                  fontSize={10}
                  tickLine={false}
                  width={110}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#020617',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} name="Hits" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Level Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="border-b border-slate-800 pb-2">
            <h3 className="text-sm font-bold text-white">Risk Severity Distribution</h3>
            <p className="text-xs text-slate-400">Threat records segmented by weighted severity threshold</p>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={trends?.riskDistribution || []}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#020617',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {(trends?.riskDistribution || []).map((entry: any, index: number) => (
                    <Cell key={`cell-${index}`} fill={entry.color || '#06b6d4'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Top Impersonation Patterns List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="border-b border-slate-800 pb-2">
          <h3 className="text-sm font-bold text-white">Top Impersonation Vectors Observed</h3>
          <p className="text-xs text-slate-400">Attacker tactics identified across monitored external digital attack surface</p>
        </div>

        <div className="space-y-3">
          {(trends?.topPatterns || []).map((pattern: any, idx: number) => (
            <div
              key={idx}
              className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 flex items-center justify-between gap-4"
            >
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-white flex items-center gap-2">
                  <span className="text-cyan-400 font-mono">0{idx + 1}.</span>
                  <span>{pattern.pattern}</span>
                </div>
                <p className="text-[11px] text-slate-400">{pattern.description}</p>
              </div>

              <div className="text-right shrink-0">
                <span className="font-mono text-sm font-bold text-rose-400 tabular-nums">
                  {pattern.count}
                </span>
                <span className="text-[10px] text-slate-500 block">Detections</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
