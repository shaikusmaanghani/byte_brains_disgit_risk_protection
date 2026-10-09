import React, { useState } from 'react';
import {
  Shield,
  Smartphone,
  Globe,
  Share2,
  AlertOctagon,
  Users,
  ExternalLink,
  Info,
  CheckCircle,
} from 'lucide-react';
import { ThreatGraphNode, ThreatGraphLink } from '../types';

interface ThreatGraphProps {
  nodes: ThreatGraphNode[];
  links: ThreatGraphLink[];
  onSelectFinding?: (findingId: string) => void;
}

export const ThreatGraph: React.FC<ThreatGraphProps> = ({
  nodes,
  links,
  onSelectFinding,
}) => {
  const [selectedNode, setSelectedNode] = useState<ThreatGraphNode | null>(null);

  // Position nodes in a clean radial-hierarchical layout
  const width = 840;
  const height = 540;
  const centerX = width / 2;
  const centerY = height / 2;

  // Group nodes by category for clean positioning
  const brandNode = nodes.find((n) => n.type === 'brand') || { id: 'root', label: 'Brand', type: 'brand' };
  const officialNodes = nodes.filter((n) => n.type.startsWith('official_'));
  const threatNodes = nodes.filter((n) => n.type === 'fake_app' || n.type === 'suspicious_social');
  const entityNodes = nodes.filter((n) => n.type === 'suspicious_publisher' || n.type === 'similar_domain');

  const nodePositions: Record<string, { x: number; y: number }> = {};

  // Root node in center
  nodePositions[brandNode.id] = { x: centerX, y: centerY };

  // Place official nodes on the left semicircle
  officialNodes.forEach((node, i) => {
    const total = officialNodes.length;
    const angle = Math.PI - 0.7 + (i / Math.max(1, total - 1)) * 1.4; // left arc
    const radius = 220;
    nodePositions[node.id] = {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    };
  });

  // Place threat nodes on the right semicircle
  threatNodes.forEach((node, i) => {
    const total = threatNodes.length;
    const angle = -0.7 + (i / Math.max(1, total - 1)) * 1.4; // right arc
    const radius = 220;
    nodePositions[node.id] = {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    };
  });

  // Place peripheral entity nodes (publishers, domains) outer right
  entityNodes.forEach((node, i) => {
    const total = entityNodes.length;
    const angle = -0.9 + (i / Math.max(1, total - 1)) * 1.8;
    const radius = 340;
    nodePositions[node.id] = {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    };
  });

  const getNodeStyle = (node: ThreatGraphNode) => {
    switch (node.type) {
      case 'brand':
        return {
          fill: 'rgba(6, 182, 212, 0.15)',
          stroke: '#06b6d4',
          icon: Shield,
          color: 'text-cyan-400',
        };
      case 'official_app':
        return {
          fill: 'rgba(16, 185, 129, 0.15)',
          stroke: '#10b981',
          icon: Smartphone,
          color: 'text-emerald-400',
        };
      case 'official_domain':
        return {
          fill: 'rgba(59, 130, 246, 0.15)',
          stroke: '#3b82f6',
          icon: Globe,
          color: 'text-blue-400',
        };
      case 'official_social':
        return {
          fill: 'rgba(14, 165, 233, 0.15)',
          stroke: '#0ea5e9',
          icon: Share2,
          color: 'text-sky-400',
        };
      case 'fake_app':
        return {
          fill: 'rgba(244, 63, 94, 0.2)',
          stroke: '#f43f5e',
          icon: AlertOctagon,
          color: 'text-rose-400',
        };
      case 'suspicious_social':
        return {
          fill: 'rgba(244, 63, 94, 0.2)',
          stroke: '#f43f5e',
          icon: AlertOctagon,
          color: 'text-rose-400',
        };
      case 'suspicious_publisher':
        return {
          fill: 'rgba(249, 115, 22, 0.2)',
          stroke: '#f97316',
          icon: Users,
          color: 'text-orange-400',
        };
      case 'similar_domain':
        return {
          fill: 'rgba(234, 179, 8, 0.2)',
          stroke: '#eab308',
          icon: Globe,
          color: 'text-amber-400',
        };
      default:
        return {
          fill: 'rgba(100, 116, 139, 0.2)',
          stroke: '#64748b',
          icon: Info,
          color: 'text-slate-400',
        };
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden relative shadow-lg">
      <div className="p-4 border-b border-slate-800/80 flex items-center justify-between bg-slate-950/60">
        <div>
          <div className="text-sm font-semibold text-white flex items-center gap-2">
            <span>Threat Relationship Topology</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              Interactive Entity Graph
            </span>
          </div>
          <div className="text-xs text-slate-400">
            Click any node to inspect relationship telemetry, publisher chains, and threat indicators.
          </div>
        </div>

        {/* Legend */}
        <div className="hidden md:flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span className="text-slate-400">Official Assets</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
            <span className="text-slate-400">Active Threats</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
            <span className="text-slate-400">Unauthorized Entities</span>
          </div>
        </div>
      </div>

      <div className="relative overflow-x-auto flex justify-center py-4 bg-slate-950/40">
        <svg width={width} height={height} className="select-none">
          <defs>
            <radialGradient id="nodeGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Links */}
          {links.map((link, idx) => {
            const sourcePos = nodePositions[link.source];
            const targetPos = nodePositions[link.target];
            if (!sourcePos || !targetPos) return null;

            const isSelected =
              selectedNode &&
              (selectedNode.id === link.source || selectedNode.id === link.target);

            return (
              <g key={idx}>
                <line
                  x1={sourcePos.x}
                  y1={sourcePos.y}
                  x2={targetPos.x}
                  y2={targetPos.y}
                  stroke={
                    link.riskFlag
                      ? isSelected
                        ? '#f43f5e'
                        : 'rgba(244, 63, 94, 0.4)'
                      : isSelected
                      ? '#06b6d4'
                      : 'rgba(71, 85, 105, 0.4)'
                  }
                  strokeWidth={isSelected ? 2 : 1.2}
                  strokeDasharray={link.riskFlag ? '4,4' : 'none'}
                />
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;
            const style = getNodeStyle(node);
            const isSelected = selectedNode?.id === node.id;
            const isRoot = node.type === 'brand';
            const nodeRadius = isRoot ? 26 : 18;

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer group"
              >
                {/* Glow ring on threat or selected */}
                {(isSelected || (node.riskLevel === 'critical' && !isSelected)) && (
                  <circle
                    r={nodeRadius + 8}
                    fill="none"
                    stroke={style.stroke}
                    strokeWidth={1}
                    className="animate-pulse opacity-70"
                  />
                )}

                <circle
                  r={nodeRadius}
                  fill={style.fill}
                  stroke={style.stroke}
                  strokeWidth={isSelected ? 2.5 : 1.5}
                  className="transition-transform duration-200 group-hover:scale-110"
                />

                {/* Node Label Text */}
                <text
                  y={nodeRadius + 14}
                  textAnchor="middle"
                  className={`text-[10px] font-mono font-medium fill-slate-300 drop-shadow ${
                    isSelected ? 'font-bold fill-white' : ''
                  }`}
                >
                  {node.label.length > 20 ? node.label.slice(0, 18) + '...' : node.label}
                </text>

                {node.riskScore !== undefined && (
                  <text
                    y={-nodeRadius - 4}
                    textAnchor="middle"
                    className="text-[9px] font-mono font-bold fill-rose-400"
                  >
                    Risk: {node.riskScore}
                  </text>
                )}
              </g>
            );
          })}
        </svg>

        {/* Selected Node Inspector Drawer */}
        {selectedNode && (
          <div className="absolute right-4 top-16 w-80 bg-slate-900/95 border border-slate-700/80 rounded-xl p-4 shadow-2xl backdrop-blur-md z-10">
            <div className="flex items-start justify-between mb-3 border-b border-slate-800 pb-2">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  Node Telemetry
                </span>
                <div className="text-sm font-bold text-white mt-0.5">{selectedNode.label}</div>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white text-xs px-1.5 py-0.5 rounded bg-slate-800"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2.5 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Entity Type:</span>
                <span className="text-slate-200 font-mono capitalize">
                  {selectedNode.type.replace(/_/g, ' ')}
                </span>
              </div>

              {selectedNode.riskScore !== undefined && (
                <div className="flex justify-between">
                  <span className="text-slate-400">Assigned Risk:</span>
                  <span className="text-rose-400 font-mono font-bold">
                    {selectedNode.riskScore} / 100 ({selectedNode.riskLevel})
                  </span>
                </div>
              )}

              {selectedNode.meta && (
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-300 space-y-1">
                  {Object.entries(selectedNode.meta).map(([k, v]) => (
                    <div key={k} className="flex justify-between">
                      <span className="text-slate-400 capitalize">{k}:</span>
                      <span className="font-mono text-slate-200 max-w-[160px] truncate text-right">
                        {String(v)}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {selectedNode.type.startsWith('fake_') && onSelectFinding && (
                <button
                  onClick={() => {
                    const id = selectedNode.id.replace('node-threat-', '');
                    onSelectFinding(id);
                  }}
                  className="w-full mt-2 py-1.5 px-3 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
                >
                  <span>Open Full Investigation</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
