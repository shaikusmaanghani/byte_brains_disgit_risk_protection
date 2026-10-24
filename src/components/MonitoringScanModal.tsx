import React, { useEffect, useState } from 'react';
import {
  RefreshCw,
  CheckCircle2,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Database,
  Cpu,
  Layers,
} from 'lucide-react';
import { apiClient } from '../services/apiClient';

interface MonitoringScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanCompleted: () => void;
}

export const MonitoringScanModal: React.FC<MonitoringScanModalProps> = ({
  isOpen,
  onClose,
  onScanCompleted,
}) => {
  const [stepIndex, setStepIndex] = useState(0);
  const [isDone, setIsDone] = useState(false);
  const [scanResult, setScanResult] = useState<Awaited<ReturnType<typeof apiClient.runMonitoringScan>> | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const steps = [
    { label: 'Checking source adapters...', detail: 'Querying the configured live domain and app-store sources' },
    { label: 'Validating candidates...', detail: 'Excluding allowlisted official brand assets' },
    { label: 'Comparing brand identity...', detail: 'Scoring names, descriptions, publishers, and available logos' },
    { label: 'Updating findings...', detail: 'Upserting records and deduplicating alerts' },
    { label: 'Refreshing radar...', detail: 'Aggregating current counts and source statuses from MongoDB' },
  ];

  useEffect(() => {
    if (!isOpen) {
      setStepIndex(0);
      setIsDone(false);
      setScanResult(null);
      setScanError(null);
      return;
    }

    let cancelled = false;
    const interval = setInterval(() => {
      setStepIndex((current) => Math.min(current + 1, steps.length - 1));
    }, 500);
    apiClient.runMonitoringScan()
      .then((res) => {
        if (cancelled) return;
        setScanResult(res);
        setStepIndex(steps.length - 1);
        setIsDone(true);
        onScanCompleted();
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        console.error('Scan failed:', err);
        setScanError(err instanceof Error ? err.message : 'The live scan failed.');
        setIsDone(true);
      });

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-lg p-6 shadow-2xl shadow-black/80 space-y-6 animate-in fade-in zoom-in-95 duration-200">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <RefreshCw className={`w-4 h-4 ${!isDone ? 'animate-spin' : ''}`} />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Monitoring Scan Pipeline</h3>
              <p className="text-[11px] text-slate-400 font-mono">
                LIVE SOURCE CHECK
              </p>
            </div>
          </div>
          {isDone && (
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800"
            >
              Close
            </button>
          )}
        </div>

        {/* Step Progression List */}
        <div className="space-y-3">
          {steps.map((st, idx) => {
            const isFinished = idx < stepIndex || (isDone && !scanError);
            const isCurrent = idx === stepIndex && !isDone;

            return (
              <div
                key={idx}
                className={`p-3 rounded-lg border text-xs transition-all ${
                  isFinished
                    ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-200'
                    : isCurrent
                    ? 'bg-cyan-950/30 border-cyan-500/40 text-cyan-200 shadow-sm'
                    : 'bg-slate-950/40 border-slate-800/80 text-slate-500'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {isFinished ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : isCurrent ? (
                      <div className="w-4 h-4 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-slate-700" />
                    )}
                    <span className="font-semibold">{st.label}</span>
                  </div>
                  {isFinished && <span className="text-[10px] font-mono text-emerald-400">OK</span>}
                </div>
                {isCurrent && (
                  <p className="mt-1 text-[11px] text-slate-400 pl-6 animate-pulse">
                    {st.detail}
                  </p>
                )}
              </div>
            );
          })}
        </div>

        {scanError && (
          <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-4 text-xs text-rose-200">
            <p className="font-semibold">Live scan failed</p>
            <p className="mt-1">{scanError}</p>
          </div>
        )}

        {/* Completion Result Card */}
        {isDone && scanResult && (
          <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/40 space-y-3">
            <div className="flex items-center justify-between text-xs font-semibold text-cyan-300">
              <span className="flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                {scanResult.started ? 'Live scan completed' : scanResult.scan_in_progress ? 'Live scan already running' : 'Scan cooldown active'}
              </span>
              <span className="font-mono text-slate-400 text-[11px]">
                {scanResult.summary.sources_checked.length} sources checked
              </span>
            </div>
            <p className="text-xs text-slate-300">
              Radar currently tracks {scanResult.summary.total_suspected} suspected and {scanResult.summary.confirmed_fake} confirmed detections. These counts exclude official, false-positive, and closed records.
            </p>
            <div className="flex items-center justify-between text-xs text-slate-400 border-t border-slate-800/80 pt-2 font-mono">
              <span>Last scan: {scanResult.last_scan_at ? new Date(scanResult.last_scan_at).toLocaleString() : 'not recorded'}</span>
              <span className={scanResult.started ? 'text-emerald-400' : 'text-amber-400'}>
                {scanResult.started ? 'LIVE DATA' : 'NO NEW SCAN STARTED'}
              </span>
            </div>
            <ul className="space-y-1 border-t border-slate-800/80 pt-2 text-[10px]">
              {scanResult.summary.sources_checked.map((source) => (
                <li key={source.name} className="flex justify-between gap-3">
                  <span className="truncate text-slate-400">{source.name}{source.detail ? ` · ${source.detail}` : ''}</span>
                  <span className={source.status === 'ok' ? 'shrink-0 text-emerald-400' : source.status === 'failed' ? 'shrink-0 text-rose-400' : 'shrink-0 text-slate-500'}>{source.status}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex justify-end pt-2">
          {isDone ? (
            <button
              onClick={onClose}
              className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs transition-colors"
            >
              {scanError ? 'Close' : 'View Findings'}
            </button>
          ) : (
            <div className="text-xs text-slate-500 font-mono flex items-center gap-2">
              <span>Contacting live source adapters...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
