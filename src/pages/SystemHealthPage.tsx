import React, { useEffect, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  Layers,
  Radio,
  RefreshCw,
  Server,
  Zap,
} from 'lucide-react';
import { SystemHealthReport } from '../types';
import { apiClient } from '../services/apiClient';

export const SystemHealthPage: React.FC = () => {
  const [health, setHealth] = useState<SystemHealthReport | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchHealth = () => {
    setIsRefreshing(true);
    apiClient.getSystemHealth()
      .then((res) => setHealth(res))
      .catch((err) => console.error(err))
      .finally(() => setIsRefreshing(false));
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>SOC System Health & Telemetry</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time diagnostics across REST API gateway, persistent data store, detection engine pipeline, and background schedulers.
          </p>
        </div>

        <button
          onClick={fetchHealth}
          disabled={isRefreshing}
          className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span>Refresh Status</span>
        </button>
      </div>

      {/* Core Component Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Backend API */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Backend API</span>
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-emerald-400">HEALTHY</div>
          <div className="text-[11px] text-slate-400 font-mono">
            Latency: {health?.apiLatencyMs || 14}ms · Express/FastAPI
          </div>
        </div>

        {/* Database */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-emerald-400" />
              <span>Database Store</span>
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-emerald-400">HEALTHY</div>
          <div className="text-[11px] text-slate-400 font-mono">
            Latency: {health?.databaseLatencyMs || 3}ms · SQLite / JSON
          </div>
        </div>

        {/* Detection Engine */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Detection Engine</span>
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-emerald-400">HEALTHY</div>
          <div className="text-[11px] text-slate-400 font-mono">
            Evaluations: {health?.totalEngineEvaluations || 320} completed
          </div>
        </div>

        {/* Monitoring Scheduler */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-purple-400" />
              <span>Scheduler</span>
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-emerald-400">HEALTHY</div>
          <div className="text-[11px] text-slate-400 font-mono">
            Workers: {health?.activeWorkers || 4} active threads
          </div>
        </div>
      </div>

      {/* Operational Metrics Panel */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-300 border-b border-slate-800 pb-2">
          Diagnostic Event Logs & Run History
        </div>

        <div className="space-y-2.5 text-xs font-mono">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400">Last Surface Scan:</span>
            <span className="text-cyan-400">{health?.lastScanTimestamp || 'Just now'}</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400">API Gateway Version:</span>
            <span className="text-white">v3.8.4-RELEASE</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400">Data Sources Operational Status:</span>
            <span className="text-amber-400">7 Connected (Simulated Mode)</span>
          </div>
        </div>
      </div>
    </div>
  );
};
