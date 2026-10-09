import React from 'react';
import {
  Cpu,
  ShieldCheck,
  Binary,
  Layers,
  ArrowRight,
  GitBranch,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';

export const ArchitecturePage: React.FC = () => {
  const scoringWeights = [
    { factor: 'Name & Handle Similarity', max: 25, formula: 'Damerau-Levenshtein edit distance + Token containment', rationale: 'Core indicator of visual deception and brand theft' },
    { factor: 'Publisher Mismatch', max: 20, formula: 'Whitelist lookup vs registered corporate entities', rationale: 'Unauthorized third parties distributing apps with corporate brand names' },
    { factor: 'Developer Mismatch', max: 15, formula: 'Known developer team signature match', rationale: 'Rogue development accounts uploading repackaged clones' },
    { factor: 'Description & Lure Mimicry', max: 15, formula: 'Jaccard token intersection + Phishing lures regex', rationale: 'Mimicking official banking phrasing, "urgent verification", or fake bonuses' },
    { factor: 'Logo / Icon Signature', max: 10, formula: 'Perceptual hash & visual brand emblem comparison', rationale: 'Visual trademark infringement on app icons and profile avatars' },
    { factor: 'Package / Bundle ID Mismatch', max: 5, formula: 'Direct comparison against registered production package IDs', rationale: 'Spoofed reverse-DNS naming schemes (e.g. com.fake.acme.bank)' },
    { factor: 'Destination Domain Mismatch', max: 5, formula: 'DNS verification vs corporate authorized domain records', rationale: 'Redirects to third-party phishing or unauthenticated endpoints' },
    { factor: 'Suspicious Permissions / Hotlines', max: 5, formula: 'SMS interception & accessibility abuse check', rationale: 'Malware features disguised as legitimate retail banking utilities' },
  ];

  const homoglyphExamples = [
    { target: 'AcmeFinanciaI', substituted: 'Latin uppercase "I" for lowercase "l"', attackType: 'Visual Spoofing / Typosquatting', normalized: 'AcmeFinancial' },
    { target: 'Аcmе Finаnciаl', substituted: 'Cyrillic "а" (U+0430) and "е" (U+0435)', attackType: 'IDN Homograph Phishing', normalized: 'Acme Financial' },
    { target: 'Acme Finanical', substituted: 'Adjacent character transposition', attackType: 'Fat-Finger Typo Squatting', normalized: 'Acme Financial' },
    { target: 'Acme Financial Support', substituted: 'Added word modifier', attackType: 'Social Engineering Lure', normalized: 'Acme Financial' },
  ];

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <span>Threat Detection Architecture & Formulas</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Detailed technical overview of the multi-stage SentinelShield threat scoring pipeline, homoglyph normalization matrices, and explainability guarantees.
        </p>
      </div>

      {/* Detection Pipeline Overview */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-300 border-b border-slate-800 pb-2">
          End-to-End Pipeline Stages
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-cyan-400 block font-bold">STAGE 01</span>
            <span className="font-bold text-white block">Candidate Extraction</span>
            <p className="text-[11px] text-slate-400">
              Parses store metadata, manifest permissions, package IDs, publisher identities, and external URLs.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-cyan-400 block font-bold">STAGE 02</span>
            <span className="font-bold text-white block">Unicode & Homoglyph Normalization</span>
            <p className="text-[11px] text-slate-400">
              Maps Cyrillic, Greek, and confusable glyphs (e.g. uppercase I for lowercase l) to base Latin ASCII.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-emerald-400 block font-bold">STAGE 03</span>
            <span className="font-bold text-white block">Official Exclusion Gate</span>
            <p className="text-[11px] text-slate-400">
              Matches package ID + publisher against verified brand credentials. Official assets immediately exit with Score = 0.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-rose-400 block font-bold">STAGE 04</span>
            <span className="font-bold text-white block">Weighted Risk Scoring</span>
            <p className="text-[11px] text-slate-400">
              Computes 8 independent threat vectors, builds Impersonation Radar, and generates explainable evidence.
            </p>
          </div>
        </div>
      </div>

      {/* Scoring Weights Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-white">
              Algorithmic Scoring Weights (Max: 100 Pts)
            </h3>
            <p className="text-[11px] text-slate-400">
              Never flags solely on name similarity; requires compounding signals to prevent false positives.
            </p>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
            Deterministic & Explainable
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-2.5">Threat Vector</th>
                <th className="px-4 py-2.5">Weight</th>
                <th className="px-4 py-2.5">Evaluation Algorithm</th>
                <th className="px-4 py-2.5">SOC Security Justification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {scoringWeights.map((w, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-bold text-white">{w.factor}</td>
                  <td className="px-4 py-3 font-mono text-cyan-400 font-bold">0–{w.max} pts</td>
                  <td className="px-4 py-3 text-slate-300 font-mono text-[11px]">{w.formula}</td>
                  <td className="px-4 py-3 text-slate-400 text-[11px]">{w.rationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Homoglyph & Confusables Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="border-b border-slate-800 pb-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-white">
            Homoglyph & Typo-Squatting Detection Matrix
          </h3>
          <p className="text-[11px] text-slate-400">
            Demonstration of Unicode confusable character handling and transposition detection.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {homoglyphExamples.map((item, idx) => (
            <div key={idx} className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
              <div className="flex items-center justify-between font-mono">
                <span className="text-rose-400 font-bold text-sm">"{item.target}"</span>
                <span className="text-[10px] text-cyan-400 uppercase">{item.attackType}</span>
              </div>
              <div className="text-slate-400 text-[11px]">Substituted: {item.substituted}</div>
              <div className="text-emerald-400 font-mono text-[11px]">Normalized Ground Truth: "{item.normalized}"</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
