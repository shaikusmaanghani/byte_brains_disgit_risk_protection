import React from 'react';
import { RiskLevel } from '../types';

interface RadarData {
  nameSimilarity: number;
  publisherMismatch: number;
  developerMismatch: number;
  descriptionSimilarity: number;
  domainMismatch: number;
  packageMismatch: number;
  logoSimilarity: number;
  suspiciousKeywords: number;
}

interface RadarProps {
  score: number;
  riskLevel: RiskLevel;
  breakdown: RadarData;
  size?: number;
}

export const RadarChart: React.FC<RadarProps> = ({
  score,
  riskLevel,
  breakdown,
  size = 280,
}) => {
  const axes = [
    { key: 'nameSimilarity', label: 'Name Similarity', max: 25, value: breakdown.nameSimilarity },
    { key: 'publisherMismatch', label: 'Publisher Mismatch', max: 20, value: breakdown.publisherMismatch },
    { key: 'developerMismatch', label: 'Developer Mismatch', max: 15, value: breakdown.developerMismatch },
    { key: 'descriptionSimilarity', label: 'Description Mimicry', max: 15, value: breakdown.descriptionSimilarity },
    { key: 'logoSimilarity', label: 'Logo Similarity', max: 10, value: breakdown.logoSimilarity },
    { key: 'domainMismatch', label: 'Domain Mismatch', max: 5, value: breakdown.domainMismatch },
    { key: 'packageMismatch', label: 'Package Mismatch', max: 5, value: breakdown.packageMismatch },
    { key: 'suspiciousKeywords', label: 'Phishing Lures', max: 5, value: breakdown.suspiciousKeywords },
  ];

  const center = size / 2;
  const radius = size * 0.38;
  const totalAxes = axes.length;

  // Compute polygon points for normalized values
  const polygonPoints = axes
    .map((axis, i) => {
      const angle = (i * 2 * Math.PI) / totalAxes - Math.PI / 2;
      const normalizedRatio = Math.min(1, Math.max(0, axis.value / axis.max));
      const r = radius * (0.2 + 0.8 * normalizedRatio);
      const x = center + r * Math.cos(angle);
      const y = center + r * Math.sin(angle);
      return `${x},${y}`;
    })
    .join(' ');

  const riskColors = {
    critical: { stroke: '#f43f5e', fill: 'rgba(244, 63, 94, 0.25)', text: 'text-rose-400' },
    high: { stroke: '#f97316', fill: 'rgba(249, 115, 22, 0.25)', text: 'text-orange-400' },
    medium: { stroke: '#eab308', fill: 'rgba(234, 179, 8, 0.25)', text: 'text-amber-400' },
    low: { stroke: '#06b6d4', fill: 'rgba(6, 182, 212, 0.25)', text: 'text-cyan-400' },
    informational: { stroke: '#10b981', fill: 'rgba(16, 185, 129, 0.25)', text: 'text-emerald-400' },
  };

  const currentTheme = riskColors[riskLevel] || riskColors.informational;

  return (
    <div className="relative flex flex-col items-center justify-center p-2">
      <svg width={size} height={size} className="overflow-visible">
        {/* Concentric grid circles */}
        {[0.25, 0.5, 0.75, 1.0].map((step, idx) => (
          <circle
            key={idx}
            cx={center}
            cy={center}
            r={radius * step}
            fill="none"
            stroke="rgba(51, 65, 85, 0.4)"
            strokeDasharray={idx < 3 ? '3,3' : 'none'}
            strokeWidth={1}
          />
        ))}

        {/* Radial axes lines */}
        {axes.map((_, i) => {
          const angle = (i * 2 * Math.PI) / totalAxes - Math.PI / 2;
          const x = center + radius * Math.cos(angle);
          const y = center + radius * Math.sin(angle);
          return (
            <line
              key={i}
              x1={center}
              y1={center}
              x2={x}
              y2={y}
              stroke="rgba(71, 85, 105, 0.4)"
              strokeWidth={1}
            />
          );
        })}

        {/* Filled Data Polygon */}
        <polygon
          points={polygonPoints}
          fill={currentTheme.fill}
          stroke={currentTheme.stroke}
          strokeWidth={2}
          strokeLinejoin="round"
          className="transition-all duration-500 ease-out"
        />

        {/* Data Vertices */}
        {axes.map((axis, i) => {
          const angle = (i * 2 * Math.PI) / totalAxes - Math.PI / 2;
          const normalizedRatio = Math.min(1, Math.max(0, axis.value / axis.max));
          const r = radius * (0.2 + 0.8 * normalizedRatio);
          const x = center + r * Math.cos(angle);
          const y = center + r * Math.sin(angle);
          return (
            <circle
              key={i}
              cx={x}
              cy={y}
              r={3}
              fill={currentTheme.stroke}
              className="drop-shadow"
            />
          );
        })}

        {/* Labels */}
        {axes.map((axis, i) => {
          const angle = (i * 2 * Math.PI) / totalAxes - Math.PI / 2;
          const labelDist = radius + 22;
          const x = center + labelDist * Math.cos(angle);
          const y = center + labelDist * Math.sin(angle);
          const isRight = Math.cos(angle) > 0.1;
          const isLeft = Math.cos(angle) < -0.1;

          return (
            <text
              key={i}
              x={x}
              y={y + 3}
              textAnchor={isRight ? 'start' : isLeft ? 'end' : 'middle'}
              className="text-[9px] fill-slate-400 font-mono"
            >
              {axis.label}
            </text>
          );
        })}
      </svg>

      {/* Prominent Center Score Badge */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <div className="w-16 h-16 rounded-full bg-slate-950/90 border border-slate-700/80 backdrop-blur-sm flex flex-col items-center justify-center shadow-lg shadow-black/80">
          <span className="font-mono text-xl font-black text-white tabular-nums tracking-tight">
            {score}
          </span>
          <span className={`text-[9px] font-bold uppercase tracking-wider ${currentTheme.text}`}>
            {riskLevel}
          </span>
        </div>
      </div>
    </div>
  );
};
