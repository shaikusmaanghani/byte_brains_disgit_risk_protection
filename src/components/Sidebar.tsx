import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Smartphone,
  Share2,
  Scan,
  GitGraph,
  BarChart3,
  BookmarkCheck,
  Radio,
  FileText,
  Activity,
  Cpu,
  Building2,
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'findings'
  | 'threat_graph'
  | 'twin_scanner'
  | 'social_monitoring'
  | 'app_monitoring'
  | 'brand_profile'
  | 'analytics'
  | 'watchlists'
  | 'sources'
  | 'reports'
  | 'system_health'
  | 'how_it_works';

interface SidebarProps {
  activePage: PageId;
  onSelectPage: (page: PageId) => void;
  threatCounts: {
    critical: number;
    high: number;
    active: number;
  };
}

export const Sidebar: React.FC<SidebarProps> = ({
  activePage,
  onSelectPage,
  threatCounts,
}) => {
  const navSections = [
    {
      category: 'Command & Operations',
      items: [
        { id: 'dashboard' as PageId, label: 'Overview', icon: LayoutDashboard },
        {
          id: 'findings' as PageId,
          label: 'Threat Findings',
          icon: ShieldAlert,
          badge: threatCounts.active > 0 ? threatCounts.active : undefined,
          badgeAlert: threatCounts.critical > 0,
        },
        { id: 'threat_graph' as PageId, label: 'Threat Graph', icon: GitGraph },
        { id: 'twin_scanner' as PageId, label: 'Brand Twin Scanner', icon: Scan },
      ],
    },
    {
      category: 'Surface Surveillance',
      items: [
        { id: 'app_monitoring' as PageId, label: 'App Monitoring', icon: Smartphone },
        { id: 'social_monitoring' as PageId, label: 'Social Monitoring', icon: Share2 },
        { id: 'watchlists' as PageId, label: 'Watchlists', icon: BookmarkCheck },
        { id: 'sources' as PageId, label: 'Data Sources', icon: Radio },
      ],
    },
    {
      category: 'Brand & Intelligence',
      items: [
        { id: 'brand_profile' as PageId, label: 'Brand Profile', icon: Building2 },
        { id: 'analytics' as PageId, label: 'Detection Analytics', icon: BarChart3 },
        { id: 'reports' as PageId, label: 'Executive Reports', icon: FileText },
      ],
    },
    {
      category: 'Governance & Engine',
      items: [
        { id: 'how_it_works' as PageId, label: 'Detection Architecture', icon: Cpu },
        { id: 'system_health' as PageId, label: 'System Health', icon: Activity },
      ],
    },
  ];

  return (
    <aside className="w-64 bg-slate-950/80 border-r border-slate-800/80 flex flex-col shrink-0 overflow-y-auto">
      <div className="p-4 space-y-6">
        {navSections.map((section) => (
          <div key={section.category}>
            <div className="px-3 mb-2 text-[11px] font-semibold tracking-wider text-slate-400 uppercase">
              {section.category}
            </div>
            <nav className="space-y-1">
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive = activePage === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectPage(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                      isActive
                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-semibold'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                      <span>{item.label}</span>
                    </div>

                    {item.badge !== undefined && (
                      <span
                        className={`px-1.5 py-0.2 rounded font-mono text-[10px] font-bold ${
                          item.badgeAlert
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>
        ))}
      </div>

      <div className="mt-auto p-4 border-t border-slate-800/60 bg-slate-950">
        <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1">
            <span>Engine Mode</span>
            <span className="text-emerald-400 font-mono font-bold">ONLINE</span>
          </div>
          <div className="text-xs text-slate-200 font-medium">Acme Financial Corp</div>
          <div className="text-[10px] text-slate-400">Continuous 24/7 DRP Sentinel</div>
        </div>
      </div>
    </aside>
  );
};
