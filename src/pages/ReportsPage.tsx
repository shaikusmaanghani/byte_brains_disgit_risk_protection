import React, { useState } from 'react';
import {
  FileText,
  Download,
  Printer,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Building2,
  Calendar,
  Lock,
} from 'lucide-react';
import { BrandProfile, Finding } from '../types';

interface ReportsPageProps {
  brand: BrandProfile;
  findings: Finding[];
}

export const ReportsPage: React.FC<ReportsPageProps> = ({
  brand,
  findings,
}) => {
  const [reportFormat, setReportFormat] = useState<'executive' | 'technical'>('executive');

  const criticalCount = findings.filter((f) => f.riskLevel === 'critical').length;
  const highCount = findings.filter((f) => f.riskLevel === 'high').length;
  const activeCount = findings.filter((f) => f.status !== 'resolved' && f.status !== 'dismissed').length;

  const handlePrint = () => {
    window.print();
  };

  const downloadJSON = () => {
    const payload = {
      reportTitle: 'SentinelShield Digital Risk Protection Executive Assessment',
      organization: brand.name,
      classification: 'CONFIDENTIAL // SOC RESTRICTED',
      generatedAt: new Date().toISOString(),
      summary: {
        totalThreats: findings.length,
        criticalThreats: criticalCount,
        highThreats: highCount,
        activeThreats: activeCount,
      },
      findings,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinelshield_executive_report_${Date.now()}.json`;
    a.click();
  };

  const downloadCSV = () => {
    const headers = ['ID', 'Asset Type', 'Platform', 'Candidate Name', 'Identifier', 'Publisher', 'Risk Score', 'Risk Level', 'Status', 'Recommended Action'];
    const rows = findings.map((f) => [
      f.id,
      f.assetType,
      f.platform,
      `"${f.candidateName.replace(/"/g, '""')}"`,
      `"${f.identifier}"`,
      `"${(f.publisherOrDeveloper || '').replace(/"/g, '""')}"`,
      f.riskScore,
      f.riskLevel,
      f.status,
      `"${f.recommendedAction.replace(/"/g, '""')}"`,
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinelshield_threat_assessment_${Date.now()}.csv`;
    a.click();
  };

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Header & Export Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4 print:hidden">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Executive & Compliance Threat Reports</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Generate printable PDF assessments and structured intelligence exports for board review and legal takedown submissions.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={downloadCSV}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={downloadJSON}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrint}
            className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors shadow-md shadow-cyan-500/20"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Save as PDF</span>
          </button>
        </div>
      </div>

      {/* Styled Printable Report Container */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-6 shadow-2xl print:bg-white print:text-black print:border-none print:shadow-none print:p-0">
        {/* Document Header */}
        <div className="flex items-start justify-between border-b border-slate-800 print:border-black pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 print:bg-slate-200 text-cyan-400 print:text-slate-800 font-bold">
                CONFIDENTIAL // TLP:AMBER
              </span>
              <span className="text-xs font-mono text-slate-400 print:text-slate-600">
                SENTINEL-DRP-2026-Q4
              </span>
            </div>
            <h2 className="text-2xl font-black text-white print:text-black tracking-tight mt-1">
              Brand Threat Assessment & Impersonation Audit
            </h2>
            <div className="text-xs text-slate-400 print:text-slate-600">
              Target Organization: <strong className="text-white print:text-black">{brand.name}</strong> · Date: {new Date().toLocaleDateString()}
            </div>
          </div>

          <div className="text-right">
            <div className="text-xs font-mono font-bold text-cyan-400 print:text-slate-900">
              SentinelShield SOC Engine
            </div>
            <div className="text-[10px] text-slate-500">Continuous Surface Intelligence</div>
          </div>
        </div>

        {/* Executive Summary Cards */}
        <div className="grid grid-cols-4 gap-3">
          <div className="p-3.5 rounded-xl bg-slate-950/60 print:bg-slate-100 border border-slate-800 print:border-slate-300">
            <span className="text-[10px] uppercase font-mono text-slate-400 print:text-slate-600 block">Total Detections</span>
            <span className="font-mono text-2xl font-black text-white print:text-black tabular-nums">{findings.length}</span>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950/60 print:bg-slate-100 border border-slate-800 print:border-slate-300">
            <span className="text-[10px] uppercase font-mono text-rose-400 print:text-red-600 block">Critical Threats</span>
            <span className="font-mono text-2xl font-black text-rose-400 print:text-red-600 tabular-nums">{criticalCount}</span>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950/60 print:bg-slate-100 border border-slate-800 print:border-slate-300">
            <span className="text-[10px] uppercase font-mono text-orange-400 print:text-orange-600 block">High Risk</span>
            <span className="font-mono text-2xl font-black text-orange-400 print:text-orange-600 tabular-nums">{highCount}</span>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950/60 print:bg-slate-100 border border-slate-800 print:border-slate-300">
            <span className="text-[10px] uppercase font-mono text-emerald-400 print:text-green-600 block">Monitored Assets</span>
            <span className="font-mono text-2xl font-black text-emerald-400 print:text-green-600 tabular-nums">
              {brand.officialApps.length + brand.officialSocialAccounts.length}
            </span>
          </div>
        </div>

        {/* Executive Finding Highlights */}
        <div className="space-y-3">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-300 print:text-black border-b border-slate-800 print:border-slate-300 pb-1">
            Priority Threat Detections Requiring Takedown
          </div>

          <div className="space-y-3">
            {findings.slice(0, 5).map((f) => (
              <div
                key={f.id}
                className="p-4 rounded-xl bg-slate-950/70 print:bg-slate-50 border border-slate-800 print:border-slate-300 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-xs text-white print:text-black font-mono">
                      {f.candidateName}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 print:bg-slate-200 text-slate-300 print:text-black">
                      {f.platform.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <span className="font-mono text-xs font-bold text-rose-400 print:text-red-600">
                    Risk: {f.riskScore}/100 [{f.riskLevel.toUpperCase()}]
                  </span>
                </div>

                <div className="text-xs text-slate-400 print:text-slate-700 font-mono">
                  Publisher / Identifier: {f.publisherOrDeveloper || f.identifier}
                </div>

                <p className="text-xs text-slate-300 print:text-slate-800 leading-relaxed">
                  {f.summaryExplanation}
                </p>

                <div className="text-[11px] font-mono text-cyan-400 print:text-blue-700">
                  Recommended Action: {f.recommendedAction}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Sign-off footer */}
        <div className="pt-6 border-t border-slate-800 print:border-black flex justify-between text-xs text-slate-500 font-mono">
          <span>Prepared by: Sarah Chen, Senior SOC Analyst</span>
          <span>SentinelShield Risk Engine v3.8</span>
        </div>
      </div>
    </div>
  );
};
