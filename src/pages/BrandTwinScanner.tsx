import React, { useState } from 'react';
import {
  Scan,
  Smartphone,
  Share2,
  Globe,
  Upload,
  AlertTriangle,
  CheckCircle2,
  ArrowRight,
  ShieldAlert,
  Sparkles,
  Layers,
  Save,
  Check,
} from 'lucide-react';
import { BrandProfile, AssetType, PlatformType, AnalysisResult } from '../types';
import { apiClient } from '../services/apiClient';
import { RadarChart } from '../components/RadarChart';

interface BrandTwinScannerProps {
  brand: BrandProfile;
  onFindingSaved: () => void;
}

export const BrandTwinScanner: React.FC<BrandTwinScannerProps> = ({
  brand,
  onFindingSaved,
}) => {
  const [assetType, setAssetType] = useState<AssetType>('mobile_application');
  const [platform, setPlatform] = useState<PlatformType>('google_play');
  const [candidateName, setCandidateName] = useState('Acme Mobile Banking');
  const [identifier, setIdentifier] = useState('com.fake.acme.bank'); // package or username
  const [developerOrPub, setDeveloperOrPub] = useState('Rogue Apps LLC');
  const [description, setDescription] = useState(
    'Official Acme secure banking application. Verify your account and receive welcome rewards. Fast money transfers.'
  );
  const [websiteUrl, setWebsiteUrl] = useState('https://security-verify-acme.biz');

  // Scanner state
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [isSaved, setIsSaved] = useState(false);

  const analysisSteps = [
    'Normalizing candidate & Unicode characters...',
    'Comparing registered brand identity & whitelist...',
    'Checking official asset exclusion gates...',
    'Running Damerau-Levenshtein name similarity...',
    'Analyzing publisher & developer authorization...',
    'Evaluating description & banking lure patterns...',
    'Auditing destination domain affiliation...',
    'Calculating weighted risk score & evidence...',
  ];

  // Presets for quick evaluation
  const loadPreset = (type: 'rogue_app' | 'homoglyph' | 'typo' | 'official') => {
    setIsSaved(false);
    setAnalysisResult(null);
    if (type === 'rogue_app') {
      setAssetType('mobile_application');
      setPlatform('google_play');
      setCandidateName('Acme Mobile Banking');
      setIdentifier('com.fake.acme.bank');
      setDeveloperOrPub('Rogue Apps LLC');
      setDescription(
        'Official Acme secure banking application. Verify your account and receive rewards. Fast balance lookups.'
      );
      setWebsiteUrl('https://phishing-acme-auth.biz');
    } else if (type === 'homoglyph') {
      setAssetType('social_profile');
      setPlatform('x_twitter');
      setCandidateName('Acme Financial');
      setIdentifier('acme_financiaI'); // Capital I
      setDeveloperOrPub('@acme_financiaI');
      setDescription(
        'Official Twitter support desk for Acme Financial. Direct message us for urgent account verification and unlocking.'
      );
      setWebsiteUrl('https://claim-acme-reward.xyz');
    } else if (type === 'typo') {
      setAssetType('mobile_application');
      setPlatform('google_play');
      setCandidateName('Acme Finanical Banking');
      setIdentifier('com.quicksoft.acme.finanical');
      setDeveloperOrPub('QuickSoft Studio');
      setDescription('Manage money and balances with Acme Finanical mobile app.');
      setWebsiteUrl('https://quicksoft.io');
    } else if (type === 'official') {
      setAssetType('mobile_application');
      setPlatform('google_play');
      setCandidateName('Acme Mobile Banking');
      setIdentifier('com.acme.mobilebanking');
      setDeveloperOrPub('Acme Financial Technologies LLC');
      setDescription('Official Acme Financial mobile banking app for checking and savings.');
      setWebsiteUrl('https://www.acmefinancial.com');
    }
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAnalyzing(true);
    setAnalysisResult(null);
    setIsSaved(false);

    // Multi-step animated sequence
    for (let i = 0; i < analysisSteps.length; i++) {
      setCurrentStep(i);
      await new Promise((res) => setTimeout(res, 220));
    }

    try {
      let res: AnalysisResult;
      if (assetType === 'mobile_application') {
        res = await apiClient.analyzeApp({
          appName: candidateName,
          packageId: identifier,
          developer: developerOrPub,
          publisher: developerOrPub,
          platform: platform as any,
          description,
          website: websiteUrl,
        });
      } else {
        res = await apiClient.analyzeSocial({
          platform,
          profileName: candidateName,
          username: identifier.replace(/^@/, ''),
          biography: description,
          links: websiteUrl ? [websiteUrl] : [],
        });
      }
      setAnalysisResult(res);
    } catch (err) {
      console.error('Analysis failed:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSaveToFindings = async () => {
    if (!analysisResult) return;
    try {
      await apiClient.createFindingFromCandidate({
        assetType,
        platform,
        candidateName,
        packageId: assetType === 'mobile_application' ? identifier : undefined,
        username: assetType === 'social_profile' ? identifier : undefined,
        publisher: developerOrPub,
        developer: developerOrPub,
        description,
        website: websiteUrl,
      });
      setIsSaved(true);
      onFindingSaved();
    } catch (err) {
      console.error('Failed to save finding:', err);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
          <Scan className="w-5 h-5 text-cyan-400" />
          <span>Brand Twin Scanner</span>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
            Target Verification Engine
          </span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Perform high-precision threat diagnostics against registered brand credentials to detect unauthorized publisher clones, homoglyphs, and phishing vectors.
        </p>

        {/* Quick Presets */}
        <div className="flex flex-wrap items-center gap-2 mt-4">
          <span className="text-[11px] font-mono text-slate-400">SOC Demonstration Presets:</span>
          <button
            onClick={() => loadPreset('rogue_app')}
            className="px-2.5 py-1 rounded-md bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-medium transition-colors"
          >
            Critical: Rogue Banking App
          </button>
          <button
            onClick={() => loadPreset('homoglyph')}
            className="px-2.5 py-1 rounded-md bg-orange-500/10 hover:bg-orange-500/20 text-orange-400 border border-orange-500/30 text-xs font-medium transition-colors"
          >
            Homoglyph: Latin I Spoof
          </button>
          <button
            onClick={() => loadPreset('typo')}
            className="px-2.5 py-1 rounded-md bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-medium transition-colors"
          >
            Typo-Squat: Finanical
          </button>
          <button
            onClick={() => loadPreset('official')}
            className="px-2.5 py-1 rounded-md bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-medium transition-colors"
          >
            Official Asset Exclusion
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Input Configuration Form */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-300 border-b border-slate-800 pb-2">
            Candidate Metadata Inspector
          </div>

          <form onSubmit={handleAnalyze} className="space-y-4">
            {/* Asset Type */}
            <div>
              <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
                Asset Classification
              </label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setAssetType('mobile_application');
                    setPlatform('google_play');
                  }}
                  className={`py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 border transition-all ${
                    assetType === 'mobile_application'
                      ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                      : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white'
                  }`}
                >
                  <Smartphone className="w-3.5 h-3.5" />
                  <span>Mobile Application</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setAssetType('social_profile');
                    setPlatform('x_twitter');
                  }}
                  className={`py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 border transition-all ${
                    assetType === 'social_profile'
                      ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                      : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white'
                  }`}
                >
                  <Share2 className="w-3.5 h-3.5" />
                  <span>Social Profile</span>
                </button>
              </div>
            </div>

            {/* Platform Dropdown */}
            <div>
              <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
                Target Platform
              </label>
              <select
                value={platform}
                onChange={(e) => setPlatform(e.target.value as any)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              >
                {assetType === 'mobile_application' ? (
                  <>
                    <option value="google_play">Google Play Store</option>
                    <option value="apple_app_store">Apple App Store</option>
                  </>
                ) : (
                  <>
                    <option value="x_twitter">X / Twitter</option>
                    <option value="instagram">Instagram</option>
                    <option value="linkedin">LinkedIn</option>
                    <option value="facebook">Facebook</option>
                    <option value="youtube">YouTube</option>
                  </>
                )}
              </select>
            </div>

            {/* Candidate Name */}
            <div>
              <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
                Candidate Name / Title
              </label>
              <input
                type="text"
                value={candidateName}
                onChange={(e) => setCandidateName(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-medium"
              />
            </div>

            {/* Identifier (Package ID or Handle) */}
            <div>
              <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
                {assetType === 'mobile_application' ? 'Package ID / Bundle Identifier' : 'Username / Profile Handle'}
              </label>
              <input
                type="text"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Publisher / Developer */}
            <div>
              <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
                Publisher / Developer Entity
              </label>
              <input
                type="text"
                value={developerOrPub}
                onChange={(e) => setDeveloperOrPub(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Destination URL */}
            <div>
              <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
                External Website / Support Link
              </label>
              <input
                type="text"
                value={websiteUrl}
                onChange={(e) => setWebsiteUrl(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Description */}
            <div>
              <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
                Description / Biography
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-sans"
              />
            </div>

            <button
              type="submit"
              disabled={isAnalyzing}
              className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-md shadow-cyan-500/20 transition-all"
            >
              <Scan className="w-4 h-4" />
              <span>{isAnalyzing ? 'Running Threat Engine...' : 'Analyze Threat'}</span>
            </button>
          </form>
        </div>

        {/* Results Console */}
        <div className="lg:col-span-7 space-y-4">
          {/* Animated Pipeline Runner */}
          {isAnalyzing && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4 shadow-xl animate-in fade-in">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin flex items-center justify-center" />
                <div>
                  <h3 className="text-sm font-bold text-white">Detection Pipeline In Progress</h3>
                  <p className="text-xs text-cyan-400 font-mono">{analysisSteps[currentStep]}</p>
                </div>
              </div>

              <div className="space-y-1.5 pt-2">
                {analysisSteps.map((step, idx) => (
                  <div
                    key={idx}
                    className={`text-[11px] font-mono flex items-center gap-2 ${
                      idx <= currentStep ? 'text-slate-300' : 'text-slate-600'
                    }`}
                  >
                    <span>{idx < currentStep ? '✓' : idx === currentStep ? '▶' : '·'}</span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Analysis Output */}
          {analysisResult && !isAnalyzing && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5 shadow-2xl animate-in fade-in">
              {/* Verdict Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      Engine Verdict
                    </span>
                    {analysisResult.isOfficialAsset && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        OFFICIAL ASSET CONFIRMED
                      </span>
                    )}
                  </div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <span>Score: {analysisResult.riskScore}/100</span>
                    <span
                      className={`text-xs px-2.5 py-0.5 rounded uppercase font-bold border ${
                        analysisResult.riskLevel === 'critical'
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                          : analysisResult.riskLevel === 'high'
                          ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                          : analysisResult.riskLevel === 'medium'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      }`}
                    >
                      {analysisResult.riskLevel}
                    </span>
                  </h2>
                  <p className="text-xs text-slate-300 mt-1">{analysisResult.summaryExplanation}</p>
                </div>

                <div className="flex items-center gap-2">
                  {!analysisResult.isOfficialAsset && (
                    <button
                      onClick={handleSaveToFindings}
                      disabled={isSaved}
                      className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                        isSaved
                          ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/30'
                          : 'bg-slate-800 hover:bg-slate-700 text-white border border-slate-700'
                      }`}
                    >
                      {isSaved ? <Check className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
                      <span>{isSaved ? 'Recorded in Findings' : 'Save as Finding'}</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Impersonation Radar & Evidence */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
                <div className="flex justify-center bg-slate-950/60 rounded-xl p-3 border border-slate-800">
                  <RadarChart
                    score={analysisResult.riskScore}
                    riskLevel={analysisResult.riskLevel}
                    breakdown={analysisResult.radarBreakdown}
                    size={220}
                  />
                </div>

                <div className="space-y-2 text-xs">
                  <div className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">
                    Top Signals Detected:
                  </div>
                  {analysisResult.signals.map((sig, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800 text-xs space-y-0.5"
                    >
                      <div className="flex items-center justify-between text-cyan-400 font-mono text-[11px] font-bold">
                        <span>{sig.type.replace(/_/g, ' ')}</span>
                        <span>+{sig.score} pts</span>
                      </div>
                      <p className="text-slate-300 text-[11px] leading-relaxed">{sig.explanation}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommendation Callout */}
              <div className="p-3.5 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-xs text-cyan-200">
                <span className="font-bold">SOC Recommended Action: </span>
                <span>{analysisResult.recommendedAction}</span>
              </div>
            </div>
          )}

          {!analysisResult && !isAnalyzing && (
            <div className="bg-slate-900 border border-slate-800/80 rounded-xl p-8 flex flex-col items-center justify-center text-center space-y-3">
              <Scan className="w-10 h-10 text-slate-600" />
              <h3 className="text-sm font-semibold text-slate-300">Scanner Ready</h3>
              <p className="text-xs text-slate-500 max-w-sm">
                Enter target application parameters or select a demonstration preset to run the full detection pipeline.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
