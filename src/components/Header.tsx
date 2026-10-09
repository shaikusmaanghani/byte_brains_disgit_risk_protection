import React from 'react';
import {
  ShieldAlert,
  Bell,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertTriangle,
  UserCheck,
} from 'lucide-react';
import { User, RiskLevel } from '../types';

interface HeaderProps {
  currentUser: User;
  onSwitchUser: (role: 'admin' | 'analyst' | 'viewer') => void;
  onRunScan: () => void;
  isScanning: boolean;
  overallThreatLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  lastScanTime: string;
}

export const Header: React.FC<HeaderProps> = ({
  currentUser,
  onSwitchUser,
  onRunScan,
  isScanning,
  overallThreatLevel,
  lastScanTime,
}) => {
  const threatBadgeColors = {
    Critical: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
    High: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    Medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    Low: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
    Informational: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  };

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/90 backdrop-blur px-6 flex items-center justify-between z-20 shrink-0 sticky top-0">
      {/* Zone 1: Brand & Threat Level Indicator */}
      <div className="flex items-center gap-5">
        <div className="flex items-center gap-3">
          <img
            src="/src/assets/images/sentinel_shield_emblem_1791484953134.jpg"
            alt="SentinelShield Emblem"
            className="w-9 h-9 rounded-lg border border-cyan-500/30 object-cover shadow-sm shadow-cyan-500/20"
            referrerPolicy="no-referrer"
          />
          <div>
            <div className="text-base font-bold tracking-tight text-white flex items-center gap-2">
              <span>SentinelShield</span>
              <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 font-normal">
                SOC v3.8
              </span>
            </div>
            <div className="text-xs text-slate-400 font-normal">Digital Risk Protection — Brand & App Defense</div>
          </div>
        </div>

        <div className="h-6 w-px bg-slate-800 hidden md:block" />

        {/* Global Threat Level Badge */}
        <div className="hidden lg:flex items-center gap-2">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Threat Level:</span>
          <div
            className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border ${threatBadgeColors[overallThreatLevel]}`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
            {overallThreatLevel}
          </div>
        </div>
      </div>

      {/* Zone 2: Scan Action & Status */}
      <div className="flex items-center gap-3">
        <button
          onClick={onRunScan}
          disabled={isScanning}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold tracking-wide border transition-all ${
            isScanning
              ? 'bg-cyan-950/60 text-cyan-400 border-cyan-500/40 cursor-wait'
              : 'bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-slate-950 font-bold border-cyan-400/50 shadow-md shadow-cyan-500/20 active:scale-95'
          }`}
          title="Dispatch automated web, app store, and social threat collector"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
          <span>{isScanning ? 'Scanning Surface...' : 'Run Monitoring Scan'}</span>
        </button>

        {/* User Role Switcher Dropdown */}
        <div className="relative group">
          <button className="flex items-center gap-2.5 px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-800 border border-slate-700/80 text-left transition-colors">
            <img
              src="/src/assets/images/soc_analyst_avatar_1791484969026.jpg"
              alt={currentUser.name}
              className="w-7 h-7 rounded-full object-cover border border-slate-600"
              referrerPolicy="no-referrer"
            />
            <div className="hidden sm:block">
              <div className="text-xs font-medium text-slate-200">{currentUser.name}</div>
              <div className="text-[10px] text-slate-400 capitalize">{currentUser.role}</div>
            </div>
          </button>

          {/* Quick role switch dropdown */}
          <div className="absolute right-0 mt-1 w-52 py-1.5 bg-slate-900 border border-slate-700 rounded-lg shadow-xl shadow-black/60 hidden group-hover:block group-focus-within:block z-50">
            <div className="px-3 py-1 text-[11px] font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800 mb-1">
              Switch Analyst Role
            </div>
            <button
              onClick={() => onSwitchUser('analyst')}
              className={`w-full text-left px-3 py-1.5 text-xs flex items-center justify-between hover:bg-slate-800 ${
                currentUser.role === 'analyst' ? 'text-cyan-400 font-semibold' : 'text-slate-300'
              }`}
            >
              <span>Sarah Chen (Analyst)</span>
              {currentUser.role === 'analyst' && <span className="text-[10px]">Active</span>}
            </button>
            <button
              onClick={() => onSwitchUser('admin')}
              className={`w-full text-left px-3 py-1.5 text-xs flex items-center justify-between hover:bg-slate-800 ${
                currentUser.role === 'admin' ? 'text-cyan-400 font-semibold' : 'text-slate-300'
              }`}
            >
              <span>Marcus Vance (Admin)</span>
              {currentUser.role === 'admin' && <span className="text-[10px]">Active</span>}
            </button>
            <button
              onClick={() => onSwitchUser('viewer')}
              className={`w-full text-left px-3 py-1.5 text-xs flex items-center justify-between hover:bg-slate-800 ${
                currentUser.role === 'viewer' ? 'text-cyan-400 font-semibold' : 'text-slate-300'
              }`}
            >
              <span>David Mercer (Viewer)</span>
              {currentUser.role === 'viewer' && <span className="text-[10px]">Active</span>}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
