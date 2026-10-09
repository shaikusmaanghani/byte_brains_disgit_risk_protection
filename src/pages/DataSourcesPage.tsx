import React from 'react';
import {
  Radio,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Shield,
  Smartphone,
  Share2,
} from 'lucide-react';
import { MonitoringSource } from '../types';

interface DataSourcesPageProps {
  sources: MonitoringSource[];
  onRefresh: () => void;
}

export const DataSourcesPage: React.FC<DataSourcesPageProps> = ({
  sources,
  onRefresh,
}) => {
  const appSources = sources.filter((s) => s.type === 'app_store');
  const socialSources = sources.filter((s) => s.type === 'social');

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
          <Radio className="w-5 h-5 text-cyan-400" />
          <span>Surveillance Data Ingestion Feeds</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Connected crawlers, store indexing pipelines, and graph API integrations. Pluggable architecture allows seamless upgrade from simulated feeds to enterprise API tokens.
        </p>

        {/* Prominent Demo Notice */}
        <div className="mt-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300 flex items-center justify-between">
          <span>
            <strong>Simulated Surveillance Pipeline Active:</strong> External sources are currently operating in high-fidelity sandbox simulation mode to prevent API rate exhaustion.
          </span>
          <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-200 border border-amber-500/40 font-bold uppercase">
            SIMULATED SOURCE MODE
          </span>
        </div>
      </div>

      {/* App Store Ingestion Pipelines */}
      <div className="space-y-3">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <Smartphone className="w-4 h-4 text-emerald-400" />
          <span>Mobile Application Store Crawlers</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {appSources.map((src) => (
            <div
              key={src.id}
              className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3 shadow-md"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold text-xs">
                    APK
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white">{src.name}</h3>
                    <span className="text-[10px] font-mono uppercase text-slate-400">
                      Sync interval: every {src.syncIntervalHours}h
                    </span>
                  </div>
                </div>

                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 font-bold">
                  SIMULATED SOURCE
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 bg-slate-950/60 p-3 rounded-lg border border-slate-800/80 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px]">Records Scanned:</span>
                  <span className="text-white font-bold tabular-nums">
                    {src.recordsScanned.toLocaleString()}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Threats Detected:</span>
                  <span className="text-rose-400 font-bold tabular-nums">
                    {src.threatsDetected}
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono pt-1">
                <span>Last Sync: {new Date(src.lastSync).toLocaleTimeString()}</span>
                <span className="text-emerald-400">Status: Operational</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Social Network Feeds */}
      <div className="space-y-3">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <Share2 className="w-4 h-4 text-sky-400" />
          <span>Social Media Graph Scrapers</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {socialSources.map((src) => (
            <div
              key={src.id}
              className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 shadow-md"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white">{src.name}</h3>
                  <span className="text-[10px] font-mono text-slate-400 block mt-0.5">
                    Platform: {src.platform.replace(/_/g, ' ')}
                  </span>
                </div>

                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 font-bold">
                  SIMULATED
                </span>
              </div>

              <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80 text-xs font-mono flex justify-between">
                <div>
                  <span className="text-slate-500 block text-[10px]">Scanned:</span>
                  <span className="text-white font-bold">{src.recordsScanned.toLocaleString()}</span>
                </div>
                <div className="text-right">
                  <span className="text-slate-500 block text-[10px]">Detections:</span>
                  <span className="text-rose-400 font-bold">{src.threatsDetected}</span>
                </div>
              </div>

              <div className="text-[10px] text-slate-400 font-mono flex justify-between pt-1">
                <span>Sync: {new Date(src.lastSync).toLocaleTimeString()}</span>
                <span className="text-emerald-400">OK</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
