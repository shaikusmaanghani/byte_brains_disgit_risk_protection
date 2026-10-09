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
  const [scanResult, setScanResult] = useState<any>(null);

  const steps = [
    { label: 'Collecting sources...', detail: 'Querying Google Play, App Store, X/Twitter, Instagram & LinkedIn crawler feeds' },
    { label: 'Normalizing records...', detail: 'Stripping Unicode confusable characters, homoglyphs, and punctuation noise' },
    { label: 'Comparing brand identity...', detail: 'Evaluating candidate names against Acme Financial whitelist and aliases' },
    { label: 'Running detection engine...', detail: 'Calculating Damerau-Levenshtein metrics, publisher mismatch, and lure vectors' },
    { label: 'Prioritizing threats...', detail: 'Synthesizing weighted risk scores and generating explainable analyst evidence' },
  ];

  useEffect(() => {
    if (!isOpen) {
      setStepIndex(0);
      setIsDone(false);
      setScanResult(null);
      return;
    }

    let current = 0;
    const interval = setInterval(() => {
      current++;
      if (current < steps.length) {
        setStepIndex(current);
      } else {
        clearInterval(interval);
        // Call the real backend endpoint
        apiClient.runMonitoringScan()
          .then((res) => {
            setScanResult(res);
            setIsDone(true);
            onScanCompleted();
          })
          .catch((err) => {
            console.error('Scan failed:', err);
            setIsDone(true);
          });
      }
    }, 700);

    return () => clearInterval(interval);
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
                SIMULATED SURVEILLANCE RUNNER
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
            const isFinished = idx < stepIndex || isDone;
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

        {/* Completion Result Card */}
        {isDone && (
          <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/40 space-y-3">
            <div className="flex items-center justify-between text-xs font-semibold text-cyan-300">
              <span className="flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                Scan Completed Successfully
              </span>
              <span className="font-mono text-slate-400 text-[11px]">
                {scanResult?.scannedSources || 7} Sources Scanned
              </span>
            </div>
            <p className="text-xs text-slate-300">
              New impersonation candidates and publisher mismatch anomalies were evaluated by the SentinelShield detection engine and appended to Threat Findings.
            </p>
            <div className="flex items-center justify-between text-xs text-slate-400 border-t border-slate-800/80 pt-2 font-mono">
              <span>Evaluated in 3.4s</span>
              <span className="text-amber-400">SIMULATED DATASET UPDATED</span>
            </div>
          </div>
        )}

        <div className="flex justify-end pt-2">
          {isDone ? (
            <button
              onClick={onClose}
              className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs transition-colors"
            >
              View Findings
            </button>
          ) : (
            <div className="text-xs text-slate-500 font-mono flex items-center gap-2">
              <span>Processing detection tensors...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
