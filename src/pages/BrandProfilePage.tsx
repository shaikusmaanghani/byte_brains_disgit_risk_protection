import React, { useState } from 'react';
import {
  Building2,
  Smartphone,
  Share2,
  Globe,
  Plus,
  Trash2,
  Save,
  CheckCircle2,
  ShieldCheck,
  AlertCircle,
} from 'lucide-react';
import { BrandProfile, OfficialApp, OfficialSocialAccount } from '../types';

interface BrandProfilePageProps {
  brand: BrandProfile;
  onUpdateBrand: (updated: Partial<BrandProfile>) => Promise<void>;
}

export const BrandProfilePage: React.FC<BrandProfilePageProps> = ({
  brand,
  onUpdateBrand,
}) => {
  const [name, setName] = useState(brand.name);
  const [officialWebsite, setOfficialWebsite] = useState(brand.officialWebsite);
  const [companyDescription, setCompanyDescription] = useState(brand.companyDescription);

  // Lists
  const [aliases, setAliases] = useState<string[]>(brand.aliases || []);
  const [officialDomains, setOfficialDomains] = useState<string[]>(brand.officialDomains || []);
  const [brandKeywords, setBrandKeywords] = useState<string[]>(brand.brandKeywords || []);
  const [productNames, setProductNames] = useState<string[]>(brand.productNames || []);
  const [knownPublishers, setKnownPublishers] = useState<string[]>(brand.knownPublishers || []);
  const [knownDevelopers, setKnownDevelopers] = useState<string[]>(brand.knownDevelopers || []);
  const [officialApps, setOfficialApps] = useState<OfficialApp[]>(brand.officialApps || []);
  const [officialSocialAccounts, setOfficialSocialAccounts] = useState<OfficialSocialAccount[]>(
    brand.officialSocialAccounts || []
  );

  // New item inputs
  const [newAlias, setNewAlias] = useState('');
  const [newDomain, setNewDomain] = useState('');
  const [newKeyword, setNewKeyword] = useState('');
  const [newProduct, setNewProduct] = useState('');
  const [newPublisher, setNewPublisher] = useState('');

  // New Official App state
  const [showAddApp, setShowAddApp] = useState(false);
  const [newApp, setNewApp] = useState<Partial<OfficialApp>>({
    appName: '',
    packageId: '',
    platform: 'google_play',
    publisher: '',
    developer: '',
    version: '1.0.0',
    category: 'Finance',
    storeUrl: '',
  });

  // New Official Social state
  const [showAddSocial, setShowAddSocial] = useState(false);
  const [newSocial, setNewSocial] = useState<Partial<OfficialSocialAccount>>({
    platform: 'x_twitter',
    handle: '',
    profileName: '',
    profileUrl: '',
    verified: true,
  });

  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const handleSaveAll = async () => {
    setIsSaving(true);
    setSaveSuccess(false);
    try {
      await onUpdateBrand({
        name,
        officialWebsite,
        companyDescription,
        aliases,
        officialDomains,
        brandKeywords,
        productNames,
        knownPublishers,
        knownDevelopers,
        officialApps,
        officialSocialAccounts,
      });
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to save brand profile:', err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleAddApp = () => {
    if (!newApp.appName || !newApp.packageId || !newApp.publisher) return;
    const item: OfficialApp = {
      id: `app-man-${Date.now()}`,
      appName: newApp.appName,
      packageId: newApp.packageId,
      platform: (newApp.platform as any) || 'google_play',
      publisher: newApp.publisher,
      developer: newApp.developer || newApp.publisher,
      version: newApp.version || '1.0.0',
      category: newApp.category || 'Finance',
      storeUrl: newApp.storeUrl || 'https://play.google.com',
    };
    setOfficialApps([...officialApps, item]);
    setNewApp({
      appName: '',
      packageId: '',
      platform: 'google_play',
      publisher: '',
      developer: '',
      version: '1.0.0',
      category: 'Finance',
      storeUrl: '',
    });
    setShowAddApp(false);
  };

  const handleAddSocial = () => {
    if (!newSocial.handle || !newSocial.profileName) return;
    const item: OfficialSocialAccount = {
      id: `soc-man-${Date.now()}`,
      platform: newSocial.platform as any,
      handle: newSocial.handle.replace(/^@/, ''),
      profileName: newSocial.profileName,
      profileUrl: newSocial.profileUrl || `https://${newSocial.platform}.com/${newSocial.handle}`,
      verified: !!newSocial.verified,
    };
    setOfficialSocialAccounts([...officialSocialAccounts, item]);
    setNewSocial({
      platform: 'x_twitter',
      handle: '',
      profileName: '',
      profileUrl: '',
      verified: true,
    });
    setShowAddSocial(false);
  };

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Building2 className="w-5 h-5 text-cyan-400" />
            <span>Brand Identity & Official Asset Registry</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Registered legitimate enterprise assets. The detection engine cross-references these credentials to enforce official asset exclusions and calculate mismatch signals.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {saveSuccess && (
            <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Saved to Registry
            </span>
          )}
          <button
            onClick={handleSaveAll}
            disabled={isSaving}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors shadow-md shadow-cyan-500/20"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{isSaving ? 'Saving...' : 'Save Brand Profile'}</span>
          </button>
        </div>
      </div>

      {/* Brand Core Identity */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-300 border-b border-slate-800 pb-2">
          Enterprise Profile Identity
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
              Primary Brand Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-medium"
            />
          </div>

          <div>
            <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
              Official Corporate Website
            </label>
            <input
              type="text"
              value={officialWebsite}
              onChange={(e) => setOfficialWebsite(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="md:col-span-2">
            <label className="block text-[11px] font-medium text-slate-400 uppercase tracking-wider mb-1">
              Official Company Description (Ground Truth for Semantic Analysis)
            </label>
            <textarea
              value={companyDescription}
              onChange={(e) => setCompanyDescription(e.target.value)}
              rows={2}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-sans"
            />
          </div>
        </div>
      </div>

      {/* Official Applications Manager */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Smartphone className="w-4 h-4 text-emerald-400" />
              <span>Registered Official Mobile Applications</span>
            </div>
            <div className="text-[11px] text-slate-400">
              Apps matching these package IDs and publishers are whitelisted with Risk Score = 0.
            </div>
          </div>

          <button
            onClick={() => setShowAddApp(!showAddApp)}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Official App</span>
          </button>
        </div>

        {/* Add App Form */}
        {showAddApp && (
          <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/30 space-y-3">
            <div className="text-xs font-bold text-cyan-400">Register Official Mobile Application</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              <input
                type="text"
                placeholder="App Name (e.g. Acme Mobile Banking)"
                value={newApp.appName}
                onChange={(e) => setNewApp({ ...newApp, appName: e.target.value })}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white"
              />
              <input
                type="text"
                placeholder="Package ID (e.g. com.acme.mobilebanking)"
                value={newApp.packageId}
                onChange={(e) => setNewApp({ ...newApp, packageId: e.target.value })}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono"
              />
              <select
                value={newApp.platform}
                onChange={(e) => setNewApp({ ...newApp, platform: e.target.value as any })}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white capitalize"
              >
                <option value="google_play">Google Play Store</option>
                <option value="apple_app_store">Apple App Store</option>
              </select>
              <input
                type="text"
                placeholder="Authorized Publisher"
                value={newApp.publisher}
                onChange={(e) => setNewApp({ ...newApp, publisher: e.target.value })}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white"
              />
              <input
                type="text"
                placeholder="Official Store URL"
                value={newApp.storeUrl}
                onChange={(e) => setNewApp({ ...newApp, storeUrl: e.target.value })}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono"
              />
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleAddApp}
                  className="w-full py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs"
                >
                  Confirm App
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {officialApps.map((app) => (
            <div
              key={app.id}
              className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 flex items-start justify-between"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-xs text-white">{app.appName}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                    {app.platform === 'google_play' ? 'Android' : 'iOS'}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-cyan-400">ID: {app.packageId}</div>
                <div className="text-[11px] text-slate-400">Publisher: {app.publisher}</div>
              </div>

              <button
                onClick={() => setOfficialApps(officialApps.filter((a) => a.id !== app.id))}
                className="text-slate-500 hover:text-rose-400 p-1"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Official Social Handles Manager */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Share2 className="w-4 h-4 text-sky-400" />
              <span>Official Social Media Accounts</span>
            </div>
            <div className="text-[11px] text-slate-400">
              Exact handles on these platforms are verified legitimate and excluded from threat alerts.
            </div>
          </div>

          <button
            onClick={() => setShowAddSocial(!showAddSocial)}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Social Handle</span>
          </button>
        </div>

        {/* Add Social Form */}
        {showAddSocial && (
          <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/30 space-y-3">
            <div className="text-xs font-bold text-cyan-400">Register Official Social Handle</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
              <select
                value={newSocial.platform}
                onChange={(e) => setNewSocial({ ...newSocial, platform: e.target.value as any })}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white capitalize"
              >
                <option value="x_twitter">X / Twitter</option>
                <option value="instagram">Instagram</option>
                <option value="linkedin">LinkedIn</option>
                <option value="facebook">Facebook</option>
                <option value="youtube">YouTube</option>
              </select>
              <input
                type="text"
                placeholder="Handle without @"
                value={newSocial.handle}
                onChange={(e) => setNewSocial({ ...newSocial, handle: e.target.value })}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono"
              />
              <input
                type="text"
                placeholder="Display Name"
                value={newSocial.profileName}
                onChange={(e) => setNewSocial({ ...newSocial, profileName: e.target.value })}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white"
              />
              <button
                type="button"
                onClick={handleAddSocial}
                className="py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs"
              >
                Confirm Handle
              </button>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          {officialSocialAccounts.map((acc) => (
            <div
              key={acc.id}
              className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between"
            >
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-xs text-white font-mono">@{acc.handle}</span>
                  {acc.verified && (
                    <span title="Verified Badge" className="inline-flex">
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                    </span>
                  )}
                </div>
                <div className="text-[10px] text-slate-400 uppercase font-mono mt-0.5">
                  {acc.platform.replace(/_/g, ' ')}
                </div>
              </div>

              <button
                onClick={() => setOfficialSocialAccounts(officialSocialAccounts.filter((a) => a.id !== acc.id))}
                className="text-slate-500 hover:text-rose-400 p-1"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Multi-token Whitelists: Domains, Aliases, Publishers, Keywords */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Official Domains */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="text-xs font-bold uppercase tracking-wider text-white">
            Authorized Domains
          </div>
          <div className="flex flex-wrap gap-1.5">
            {officialDomains.map((dom) => (
              <span
                key={dom}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-xs text-cyan-300 font-mono"
              >
                {dom}
                <button
                  onClick={() => setOfficialDomains(officialDomains.filter((d) => d !== dom))}
                  className="text-slate-500 hover:text-rose-400"
                >
                  ×
                </button>
              </span>
            ))}
          </div>
          <div className="flex gap-2 pt-1">
            <input
              type="text"
              placeholder="Add domain (e.g. acmebank.com)"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-white font-mono"
            />
            <button
              onClick={() => {
                if (newDomain) {
                  setOfficialDomains([...officialDomains, newDomain.trim()]);
                  setNewDomain('');
                }
              }}
              className="px-3 py-1 rounded-lg bg-slate-800 text-xs font-semibold text-slate-200"
            >
              Add
            </button>
          </div>
        </div>

        {/* Known Authorized Publishers */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="text-xs font-bold uppercase tracking-wider text-white">
            Authorized Publishers Whitelist
          </div>
          <div className="flex flex-wrap gap-1.5">
            {knownPublishers.map((pub) => (
              <span
                key={pub}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-xs text-emerald-300 font-mono"
              >
                {pub}
                <button
                  onClick={() => setKnownPublishers(knownPublishers.filter((p) => p !== pub))}
                  className="text-slate-500 hover:text-rose-400"
                >
                  ×
                </button>
              </span>
            ))}
          </div>
          <div className="flex gap-2 pt-1">
            <input
              type="text"
              placeholder="Add publisher entity name"
              value={newPublisher}
              onChange={(e) => setNewPublisher(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-white font-mono"
            />
            <button
              onClick={() => {
                if (newPublisher) {
                  setKnownPublishers([...knownPublishers, newPublisher.trim()]);
                  setNewPublisher('');
                }
              }}
              className="px-3 py-1 rounded-lg bg-slate-800 text-xs font-semibold text-slate-200"
            >
              Add
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
