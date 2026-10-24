import React, { useState } from 'react';
import { Bell, LogOut, RefreshCw } from 'lucide-react';
import type { DetectionAlert, Finding, User } from '../types';

interface HeaderProps {
  currentUser: User;
  alerts: DetectionAlert[];
  findings: Finding[];
  onLogout: () => void;
  onReadAlert: (alert: DetectionAlert) => void;
  onRunScan: () => void;
  isScanning: boolean;
  overallThreatLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  lastScanTime: string;
  onOpenFinding: (finding: Finding) => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentUser,
  alerts,
  findings,
  onLogout,
  onReadAlert,
  onRunScan,
  isScanning,
  overallThreatLevel,
  lastScanTime,
  onOpenFinding,
}) => {
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const threatBadgeColors = {
    Critical: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
    High: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    Medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    Low: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
    Informational: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  };
  const unread = alerts.filter((alert) => !alert.read).length;

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/90 backdrop-blur px-6 flex items-center justify-between z-20 shrink-0 sticky top-0">
      <div className="flex items-center gap-4">
        <img
          src="/src/assets/images/sentinel_shield_emblem_1791484953134.jpg"
          alt="SentinelShield"
          className="w-9 h-9 rounded-lg border border-cyan-500/30 object-cover"
        />
        <div>
          <div className="text-base font-bold text-white flex items-center gap-2">
            SentinelShield
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 font-normal">DEMO</span>
          </div>
          <div className="text-[11px] text-slate-400">Digital Risk Protection — Investigation Workspace</div>
        </div>
        <div className={`hidden lg:block ml-3 px-2.5 py-1 rounded border text-[10px] font-bold uppercase ${threatBadgeColors[overallThreatLevel]}`}>
          {overallThreatLevel} · Scan {lastScanTime}
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={onRunScan}
          disabled={isScanning}
          className="flex items-center gap-2 px-3 py-2 rounded-lg border border-cyan-500/40 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-60 text-slate-950 text-xs font-bold"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
          {isScanning ? 'Scanning…' : 'Run scan'}
        </button>
        <div className="relative">
          <button
            aria-label={`Notifications, ${unread} unread`}
            aria-expanded={notificationsOpen}
            onClick={() => setNotificationsOpen((open) => !open)}
            className="relative p-2 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200"
          >
            <Bell className="w-4 h-4" />
            {unread > 0 && <span className="absolute -top-1 -right-1 min-w-4 h-4 px-1 rounded-full bg-rose-500 text-[9px] text-white font-bold">{unread}</span>}
          </button>
          {notificationsOpen && (
            <div className="absolute right-0 mt-2 w-80 max-h-96 overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 shadow-2xl z-50">
              <div className="px-4 py-3 border-b border-slate-800 text-xs font-bold text-white">High-risk alerts</div>
              {alerts.length ? alerts.slice(0, 12).map((alert) => {
                const finding = findings.find((item) => item.id === alert.detectionId);
                return (
                  <button
                    key={alert.id}
                    onClick={() => {
                      onReadAlert(alert);
                      if (finding) onOpenFinding(finding);
                      setNotificationsOpen(false);
                    }}
                    className={`w-full text-left px-4 py-3 border-b border-slate-800/70 hover:bg-slate-800 ${alert.read ? 'opacity-60' : ''}`}
                  >
                    <span className="text-[11px] text-rose-300 font-bold">{alert.escalated ? 'ESCALATED · ' : ''}{alert.severity.toUpperCase()} · {alert.score}/100</span>
                    <span className="block mt-1 text-xs text-slate-200">{finding?.candidateName || alert.detectionId}</span>
                    <span className="block mt-1 text-[10px] text-slate-500">{new Date(alert.createdAt).toLocaleString()}</span>
                  </button>
                );
              }) : <p className="p-4 text-xs text-slate-400">No high-risk alerts.</p>}
            </div>
          )}
        </div>
        <div className="hidden sm:block text-right">
          <div className="text-xs font-semibold text-slate-200">{currentUser.name}</div>
          <div className="text-[10px] text-slate-400 capitalize">{currentUser.role}</div>
        </div>
        <button onClick={onLogout} className="p-2 rounded-lg border border-slate-700 text-slate-400 hover:text-white hover:bg-slate-800" aria-label="Log out">
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
