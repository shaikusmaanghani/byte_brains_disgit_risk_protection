import React, { useState } from 'react';
import {
  BookmarkCheck,
  Plus,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  Zap,
} from 'lucide-react';
import { WatchlistRule, RiskLevel } from '../types';

interface WatchlistsPageProps {
  watchlists: WatchlistRule[];
  onCreateWatchlist: (rule: Partial<WatchlistRule>) => Promise<void>;
}

export const WatchlistsPage: React.FC<WatchlistsPageProps> = ({
  watchlists,
  onCreateWatchlist,
}) => {
  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState('');
  const [targetType, setTargetType] = useState<any>('keyword');
  const [pattern, setPattern] = useState('');
  const [severity, setSeverity] = useState<RiskLevel>('high');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !pattern) return;
    await onCreateWatchlist({
      name,
      targetType,
      pattern,
      severity,
    });
    setName('');
    setPattern('');
    setShowAdd(false);
  };

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <BookmarkCheck className="w-5 h-5 text-cyan-400" />
            <span>Target Surveillance Watchlists</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Configure automated regex and pattern filters to intercept known bad actors, rogue developer studios, and suspicious TLD patterns.
          </p>
        </div>

        <button
          onClick={() => setShowAdd(!showAdd)}
          className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Watchlist Rule</span>
        </button>
      </div>

      {/* Add Rule Form */}
      {showAdd && (
        <form onSubmit={handleSubmit} className="p-5 rounded-xl bg-slate-900 border border-cyan-500/30 space-y-4 shadow-xl">
          <div className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
            Configure Automated Rule
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
            <input
              type="text"
              placeholder="Rule Name (e.g. Rogue Studio Alert)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white"
            />
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white capitalize"
            >
              <option value="keyword">Keywords / Lures</option>
              <option value="publisher">Publisher Name</option>
              <option value="developer">Developer Entity</option>
              <option value="domain">Domain / TLD Pattern</option>
              <option value="package_id">Package Prefix</option>
            </select>
            <input
              type="text"
              placeholder="Pattern (regex or pipe | separated)"
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              required
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white font-mono"
            />
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as any)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white capitalize"
            >
              <option value="critical">Critical Severity</option>
              <option value="high">High Severity</option>
              <option value="medium">Medium Severity</option>
            </select>
          </div>

          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowAdd(false)}
              className="px-3 py-1.5 rounded-lg bg-slate-800 text-xs text-slate-300"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs"
            >
              Create Rule
            </button>
          </div>
        </form>
      )}

      {/* Rules List */}
      <div className="space-y-3">
        {watchlists.map((rule) => (
          <div
            key={rule.id}
            className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between gap-4 shadow-sm"
          >
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white">{rule.name}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400 capitalize">
                  {rule.targetType.replace(/_/g, ' ')}
                </span>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold border ${
                    rule.severity === 'critical'
                      ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      : 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                  }`}
                >
                  {rule.severity}
                </span>
              </div>
              <p className="text-xs font-mono text-slate-400 bg-slate-950/60 px-2 py-1 rounded inline-block">
                Regex: {rule.pattern}
              </p>
            </div>

            <div className="flex items-center gap-4 text-xs font-mono">
              <div className="text-right">
                <span className="text-white font-bold tabular-nums">{rule.hitsCount}</span>
                <span className="text-[10px] text-slate-500 block">Triggered Hits</span>
              </div>
              <span className="px-2 py-1 rounded text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                ACTIVE
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
