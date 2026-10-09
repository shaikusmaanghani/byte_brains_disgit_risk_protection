import React from 'react';
import {
  Smartphone,
  ShieldAlert,
  AlertTriangle,
  Download,
  Filter,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Package,
  Layers,
} from 'lucide-react';
import { Finding } from '../types';

interface AppMonitoringProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onNavigateToScan: () => void;
}

export const AppMonitoring: React.FC<AppMonitoringProps> = ({
  findings,
  onSelectFinding,
  onNavigateToScan,
}) => {
  const appFindings = findings.filter((f) => f.assetType === 'mobile_application');
  const googlePlayCount = appFindings.filter((f) => f.platform === 'google_play').length;
  const appleCount = appFindings.filter((f) => f.platform === 'apple_app_store').length;
  const criticalApps = appFindings.filter((f) => f.riskLevel === 'critical').length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Smartphone className="w-5 h-5 text-cyan-400" />
            <span>Mobile App Store Surveillance</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Continuous threat surveillance across Google Play Store & Apple App Store to detect rogue publisher packaging and credential harvest apps.
          </p>
        </div>

        <button
          onClick={onNavigateToScan}
          className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors"
        >
          <span>Scan New App APK/Bundle</span>
        </button>
      </div>

      {/* Surface Metric Badges */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider block">App Threats Identified</span>
          <span className="font-mono text-2xl font-bold text-white tabular-nums">{appFindings.length}</span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Active candidates on record</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-rose-400 uppercase tracking-wider block">Critical App Clones</span>
          <span className="font-mono text-2xl font-bold text-rose-400 tabular-nums">{criticalApps}</span>
          <span className="text-[10px] text-rose-400/80 block mt-0.5">Publisher mismatch verified</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-cyan-400 uppercase tracking-wider block">Google Play Surface</span>
          <span className="font-mono text-2xl font-bold text-cyan-400 tabular-nums">{googlePlayCount}</span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Continuous manifest scraper</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[11px] text-emerald-400 uppercase tracking-wider block">Apple App Store</span>
          <span className="font-mono text-2xl font-bold text-emerald-400 tabular-nums">{appleCount}</span>
          <span className="text-[10px] text-slate-500 block mt-0.5">Bundle ID indexing active</span>
        </div>
      </div>

      {/* Apps Threat Cards */}
      <div className="space-y-3">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-400">
          Active Mobile Threat Detections
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {appFindings.map((finding) => (
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
                          : finding.riskLevel === 'high'
                          ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}
                    >
                      Score: {finding.riskScore}/100 [{finding.riskLevel}]
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
                    {finding.candidateName}
                  </h3>
                </div>

                <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 transition-colors" />
              </div>

              <div className="bg-slate-950/80 rounded-lg p-3 border border-slate-800/80 text-xs space-y-1.5 font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Publisher:</span>
                  <span className="text-rose-400 font-bold truncate max-w-[200px]">
                    {finding.publisherOrDeveloper || 'Rogue Studio'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Package ID:</span>
                  <span className="text-slate-200 truncate max-w-[200px]">{finding.identifier}</span>
                </div>
              </div>

              <div className="space-y-1 text-xs text-slate-300">
                <span className="text-[10px] uppercase font-bold text-slate-400 font-mono">Key Evidence:</span>
                <p className="line-clamp-2 text-[11px] leading-relaxed">
                  {finding.signals[0]?.explanation || finding.summaryExplanation}
                </p>
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800 font-mono">
                <span>First Seen: {new Date(finding.firstSeen).toLocaleDateString()}</span>
                <span className="text-cyan-400 font-semibold group-hover:underline">Deep Investigation →</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
