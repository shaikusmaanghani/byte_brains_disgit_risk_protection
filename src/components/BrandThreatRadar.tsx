import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Activity, AlertCircle, ArrowUpRight, Clock3, RefreshCw, ShieldCheck } from 'lucide-react';
import type { BrandProfile, Finding, RadarSummary } from '../types';
import { apiClient } from '../services/apiClient';

interface BrandThreatRadarProps {
  brand: BrandProfile;
  onSelectFinding: (finding: Finding) => void;
}

const platformLabels: Record<string, string> = {
  'social profile': 'Social profiles',
  'web page': 'Web pages',
  'mobile app': 'Mobile apps',
};

const severityColors: Record<string, string> = {
  critical: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  high: 'border-orange-500/30 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  low: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300',
  informational: 'border-slate-600 bg-slate-800 text-slate-300',
};

const sourceColors = {
  ok: 'text-emerald-300',
  skipped: 'text-slate-400',
  failed: 'text-rose-300',
};

function ago(timestamp: string | null): string {
  if (!timestamp) return 'not run yet';
  const minutes = Math.max(0, Math.floor((Date.now() - Date.parse(timestamp)) / 60_000));
  if (minutes < 1) return 'just now';
  if (minutes === 1) return '1 min ago';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours} hr${hours === 1 ? '' : 's'} ago`;
}

export const BrandThreatRadar: React.FC<BrandThreatRadarProps> = ({ brand, onSelectFinding }) => {
  const [summary, setSummary] = useState<RadarSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [scanError, setScanError] = useState('');
  const [scanStarting, setScanStarting] = useState(false);
  const [toast, setToast] = useState('');
  const seenIds = useRef<Set<string>>(new Set());
  const toastedKeys = useRef<Set<string>>(new Set());
  const lastCount = useRef<number | null>(null);
  const toastTimer = useRef<number | undefined>(undefined);

  const acceptSummary = useCallback((next: RadarSummary) => {
    if (lastCount.current !== null && next.total_suspected > lastCount.current) {
      const freshIds = next.recent_new_ids.filter((id) => !seenIds.current.has(id));
      const notToasted = freshIds.filter((id) => !toastedKeys.current.has(id));
      const fallbackKey = `suspected-count-${next.total_suspected}`;
      const toastCount = notToasted.length || (!next.recent_new_ids.length && !toastedKeys.current.has(fallbackKey)
        ? next.total_suspected - lastCount.current
        : 0);
      if (toastCount > 0) {
        notToasted.forEach((id) => toastedKeys.current.add(id));
        if (!notToasted.length) toastedKeys.current.add(fallbackKey);
        setToast(`+${toastCount} new suspected impersonation${toastCount === 1 ? '' : 's'}`);
        if (toastTimer.current) window.clearTimeout(toastTimer.current);
        toastTimer.current = window.setTimeout(() => setToast(''), 5000);
      }
    }
    next.recent_new_ids.forEach((id) => seenIds.current.add(id));
    lastCount.current = next.total_suspected;
    setSummary(next);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const next = await apiClient.getRadarSummary();
      acceptSummary(next);
      setError('');
      return next;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not load radar data.');
      return null;
    } finally {
      setLoading(false);
    }
  }, [acceptSummary]);

  const startScan = useCallback(async () => {
    setScanStarting(true);
    setScanError('');
    try {
      const result = await apiClient.runRadarScan();
      acceptSummary(result.summary);
      setError('');
    } catch (cause) {
      setScanError(cause instanceof Error ? cause.message : 'The radar scan could not start.');
      await refresh();
    } finally {
      setScanStarting(false);
    }
  }, [acceptSummary, refresh]);

  useEffect(() => {
    let active = true;
    const initialize = async () => {
      await refresh();
      if (active) await startScan();
    };
    void initialize();

    const poll = () => {
      if (document.visibilityState === 'visible') void refresh();
    };
    const interval = window.setInterval(poll, 15_000);
    document.addEventListener('visibilitychange', poll);
    return () => {
      active = false;
      window.clearInterval(interval);
      document.removeEventListener('visibilitychange', poll);
      if (toastTimer.current) window.clearTimeout(toastTimer.current);
    };
  }, [refresh, startScan]);

  const openFinding = async (id: string) => {
    try {
      onSelectFinding(await apiClient.getFindingById(id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not open detection details.');
    }
  };

  return (
    <section aria-labelledby="brand-threat-radar-title" className="rounded-2xl border border-cyan-700/40 bg-gradient-to-br from-cyan-950/40 via-slate-900 to-slate-950 p-4 sm:p-5 shadow-lg shadow-cyan-950/20">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-cyan-300 font-semibold">
            <Activity className="h-3.5 w-3.5" />
            Live monitoring
          </div>
          <h2 id="brand-threat-radar-title" className="mt-1 text-lg font-bold text-white">Brand Threat Radar</h2>
          <p className="mt-1 text-xs text-slate-300">
            Current signals affecting <strong className="text-white">{brand.name}</strong>
          </p>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-slate-400" aria-live="polite">
          {scanStarting || summary?.scan_in_progress ? (
            <><span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400" /> Scanning…</>
          ) : (
            <><Clock3 className="h-3.5 w-3.5" /> Last scan: {ago(summary?.last_scan_at || null)}</>
          )}
          <button type="button" aria-label="Retry radar scan" onClick={() => void startScan()} disabled={scanStarting} className="ml-1 rounded-md border border-slate-700 p-1.5 text-slate-300 hover:border-cyan-500 hover:text-cyan-200 disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${scanStarting ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {loading && !summary ? (
        <div className="mt-4 grid animate-pulse grid-cols-1 gap-3 sm:grid-cols-3">
          {[0, 1, 2].map((item) => <div key={item} className="h-20 rounded-xl bg-slate-800/70" />)}
        </div>
      ) : error && !summary ? (
        <div className="mt-4 rounded-lg border border-rose-500/30 bg-rose-950/30 p-4 text-sm text-rose-200" role="alert">
          <p className="flex items-center gap-2"><AlertCircle className="h-4 w-4" /> {error}</p>
          <button onClick={() => void refresh()} className="mt-3 rounded bg-rose-900/70 px-3 py-1.5 text-xs font-semibold hover:bg-rose-800">Retry</button>
        </div>
      ) : summary ? (
        <>
          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-cyan-700/30 bg-slate-950/60 p-3.5">
              <span className="block text-[10px] uppercase tracking-wider text-slate-400">Suspected · unconfirmed</span>
              <strong key={summary.total_suspected} className="mt-1 inline-block animate-[radar-count_450ms_ease-out] font-mono text-3xl font-black tabular-nums text-cyan-200">
                {summary.total_suspected}
              </strong>
              <span className="ml-2 text-xs text-slate-400">impersonations</span>
            </div>
            <div className="rounded-xl border border-rose-700/30 bg-slate-950/60 p-3.5">
              <span className="block text-[10px] uppercase tracking-wider text-slate-400">Analyst-confirmed</span>
              <strong key={summary.confirmed_fake} className="mt-1 inline-block animate-[radar-count_450ms_ease-out] font-mono text-3xl font-black tabular-nums text-rose-300">
                {summary.confirmed_fake}
              </strong>
              <span className="ml-2 text-xs text-slate-400">detections</span>
            </div>
            <div className="rounded-xl border border-amber-700/30 bg-slate-950/60 p-3.5">
              <span className="block text-[10px] uppercase tracking-wider text-slate-400">Logo matches</span>
              <strong key={summary.logo_matches} className="mt-1 inline-block animate-[radar-count_450ms_ease-out] font-mono text-3xl font-black tabular-nums text-amber-200">
                {summary.logo_matches}
              </strong>
              <span className="ml-2 text-xs text-slate-400">≥{summary.logo_match_threshold}% similarity</span>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap gap-2" aria-label="Counts by platform and severity">
            {Object.entries(summary.by_platform).map(([platform, count]) => (
              <span key={platform} className="rounded-full border border-slate-700 bg-slate-900 px-2.5 py-1 text-[10px] text-slate-300">
                {platformLabels[platform] || platform}: {count}
              </span>
            ))}
            {Object.entries(summary.by_severity).map(([severity, count]) => (
              <span key={severity} className={`rounded-full border px-2.5 py-1 text-[10px] capitalize ${severityColors[severity] || severityColors.informational}`}>
                {severity}: {count}
              </span>
            ))}
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[1fr_1.1fr]">
            <div>
              <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Highest risk · top 5</h3>
              {summary.top_5_highest_risk.length ? (
                <ol className="space-y-2">
                  {summary.top_5_highest_risk.map((item, index) => (
                    <li key={item.id}>
                      <button type="button" onClick={() => void openFinding(item.id)} className="flex w-full items-center gap-2 rounded-lg border border-slate-800 bg-slate-950/60 p-2 text-left hover:border-cyan-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400">
                        <span className="font-mono text-[10px] text-slate-500">{index + 1}</span>
                        <span className="flex -space-x-1.5">
                          {item.logo_url
                            ? <img src={item.logo_url} alt={`${item.name} logo`} className="h-7 w-7 rounded-full border border-slate-700 bg-slate-800 object-cover" onError={(event) => { event.currentTarget.style.display = 'none'; }} />
                            : <span aria-label="Suspect logo unavailable" className="grid h-7 w-7 place-items-center rounded-full border border-slate-700 bg-slate-800 text-[9px] text-slate-500">?</span>}
                          <img src={brand.logoUrl} alt={`${brand.name} official logo`} className="h-7 w-7 rounded-full border border-cyan-700 bg-slate-800 object-cover" onError={(event) => { event.currentTarget.style.display = 'none'; }} />
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-xs font-semibold text-slate-200">{item.name}</span>
                          <span className="block text-[10px] text-slate-500">{item.id} · {item.platform} · {item.status}{item.logo_similarity !== null ? ` · logo ${item.logo_similarity}%` : ''}</span>
                          {item.logo_similarity !== null && item.logo_similarity >= summary.logo_match_threshold && (
                            <span className="mt-0.5 inline-block rounded border border-amber-600/40 bg-amber-500/10 px-1 py-0.5 text-[8px] font-bold uppercase text-amber-300">Logo match</span>
                          )}
                          {item.demo_data && <span className="mt-0.5 inline-block rounded border border-amber-600/40 bg-amber-500/10 px-1 py-0.5 text-[8px] font-bold uppercase text-amber-300">Demo data</span>}
                        </span>
                        <span className="whitespace-nowrap font-mono text-xs font-bold text-orange-300">{item.score}</span>
                        <ArrowUpRight className="h-3.5 w-3.5 shrink-0 text-slate-500" />
                      </button>
                    </li>
                  ))}
                </ol>
              ) : (
                <div className="rounded-lg border border-dashed border-slate-700 p-4 text-xs text-slate-400">
                  No suspected or confirmed detections are currently in the radar queue.
                </div>
              )}
            </div>
            <div>
              <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Sources checked</h3>
              {summary.sources_checked.length ? (
                <ul className="space-y-2">
                  {summary.sources_checked.map((source) => (
                    <li key={source.name} className="flex items-start gap-2 rounded-lg bg-slate-950/50 px-2.5 py-2 text-[10px]">
                      <span className={`mt-0.5 font-bold uppercase ${sourceColors[source.status]}`}>{source.status}</span>
                      <span className="min-w-0">
                        <span className="block font-semibold text-slate-300">{source.name}</span>
                        <span className="text-slate-500">{source.detail}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="rounded-lg bg-slate-950/50 p-3 text-[10px] text-slate-500">Source results will appear after the first scan.</p>
              )}
            </div>
          </div>
          {scanError && <p role="alert" className="mt-3 text-xs text-rose-300">{scanError}</p>}
          {error && <p role="alert" className="mt-3 text-xs text-rose-300">{error}</p>}
          {toast && (
            <div role="status" aria-live="polite" className="fixed right-5 top-20 z-50 flex items-center gap-2 rounded-lg border border-emerald-600/50 bg-slate-900 px-4 py-3 text-sm text-emerald-200 shadow-xl">
              <ShieldCheck className="h-4 w-4" /> {toast}
            </div>
          )}
        </>
      ) : (
        <div className="mt-4 rounded-lg border border-dashed border-slate-700 p-5 text-center text-xs text-slate-400">
          Radar data is not available yet. <button onClick={() => void refresh()} className="text-cyan-300 underline">Retry</button>
        </div>
      )}
    </section>
  );
};
