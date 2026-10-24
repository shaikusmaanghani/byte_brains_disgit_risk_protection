import { lookup } from 'node:dns/promises';
import type { AssetType, BrandProfile, Finding, PlatformType } from '../src/types/index.js';
import { normalizeString, stringSimilarity } from '../src/services/detectionEngine.js';
import { isPublicAddress, safeGet } from './safeHttp.js';

export interface RadarCandidate {
  source: string;
  assetType: AssetType;
  platform: PlatformType;
  identifier: string;
  name: string;
  url: string;
  description: string;
  publisher?: string;
  logoUrl?: string;
  isDemo?: boolean;
  payload: Record<string, unknown>;
}

export interface SourceResult {
  name: string;
  status: 'ok' | 'skipped' | 'failed';
  detail: string;
  candidates: RadarCandidate[];
}

export interface SourceAdapter {
  name: string;
  fetchCandidates: (brand: BrandProfile) => Promise<SourceResult>;
}

function rootDomain(domain: string): { label: string; suffix: string } {
  const parts = domain.toLowerCase().split('.');
  return { label: parts[0], suffix: parts.slice(1).join('.') };
}

export function domainLookalikeVariants(brand: BrandProfile): string[] {
  const official = new Set(brand.officialDomains.map((domain) => domain.toLowerCase()));
  const primary = brand.officialDomains[0];
  if (!primary) return [];
  const { label, suffix } = rootDomain(primary);
  const variants = new Set<string>();
  for (let index = 1; index < label.length - 1; index++) {
    variants.add(`${label.slice(0, index)}${label.slice(index + 1)}.${suffix}`);
    variants.add(`${label.slice(0, index)}${label[index + 1]}${label[index]}${label.slice(index + 2)}.${suffix}`);
  }
  for (const tld of ['net', 'org', 'co']) variants.add(`${label}.${tld}`);
  return [...variants].filter((domain) => !official.has(domain)).slice(0, 20);
}

async function hasPublicDns(domain: string): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  try {
    const records = await Promise.race([
      lookup(domain, { all: true, verbatim: true }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('DNS lookup timed out.')), 5000);
        timer.unref();
      }),
    ]);
    return records.length > 0 && records.every(({ address }) => isPublicAddress(address));
  } catch {
    return false;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function readMeta(html: string, property: string): string | undefined {
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const key = tag.match(/\b(?:property|name)\s*=\s*["']([^"']+)["']/i)?.[1]?.toLowerCase();
    if (key !== property.toLowerCase()) continue;
    return tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)?.[1]
      ?.replace(/&amp;/g, '&')
      .trim();
  }
  return undefined;
}

async function domainCandidate(domain: string): Promise<RadarCandidate | null> {
  const pageUrl = `https://${domain}/`;
  const response = await safeGet(pageUrl, 1024 * 1024);
  if (!response.contentType.includes('html')) return null;
  const html = response.body.toString('utf8');
  const title = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1]
    ?.replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  const logoReference =
    readMeta(html, 'og:image') ||
    readMeta(html, 'twitter:image') ||
    html.match(/<link\b[^>]*rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["']/i)?.[1] ||
    '/favicon.ico';
  return {
    source: 'lookalike_domains',
    assetType: 'domain',
    platform: 'web',
    identifier: domain,
    name: title || domain,
    url: response.url,
    description: readMeta(html, 'description') || readMeta(html, 'og:description') || '',
    logoUrl: new URL(logoReference, response.url).toString(),
    payload: { domain, pageTitle: title },
  };
}

export async function fetchLookalikeDomains(brand: BrandProfile): Promise<SourceResult> {
  const variants = domainLookalikeVariants(brand);
  const ctUrl = `https://crt.sh/?q=%25${encodeURIComponent(normalizeString(brand.name))}%25&output=json`;
  let ctDomains: string[] = [];
  let ctIssue = '';
  try {
    const response = await safeGet(ctUrl, 1024 * 1024);
    const entries = JSON.parse(response.body.toString('utf8')) as Array<{ name_value?: string }>;
    ctDomains = entries
      .flatMap((entry) => (entry.name_value || '').split(/\r?\n/))
      .map((name) => name.replace(/^\*\./, '').toLowerCase().trim())
      .filter((name) => name && !brand.officialDomains.includes(name))
      .filter((name) => {
        const label = rootDomain(name).label;
        return stringSimilarity(label, rootDomain(brand.officialDomains[0] || brand.name).label) >= 0.62;
      });
  } catch (error) {
    ctIssue = error instanceof Error ? error.message : 'Certificate Transparency lookup failed.';
  }
  const candidates = [...new Set([...variants, ...ctDomains])].slice(0, 12);
  let pageFailures = 0;
  const resolved = await Promise.all(candidates.map(async (domain) => {
    if (!await hasPublicDns(domain)) return null;
    try {
      return await domainCandidate(domain);
    } catch {
      pageFailures++;
      return null;
    }
  }));
  const liveCandidates = resolved.filter((item): item is RadarCandidate => item !== null);
  const detail = [
    `${liveCandidates.length} live public domain candidate${liveCandidates.length === 1 ? '' : 's'} checked from DNS-resolving lookalikes and Certificate Transparency.`,
    ctIssue ? `Certificate Transparency lookup failed: ${ctIssue}` : '',
    pageFailures ? `${pageFailures} DNS-resolving page${pageFailures === 1 ? '' : 's'} could not be inspected.` : '',
  ].filter(Boolean).join(' ');
  return {
    name: 'Lookalike domains + Certificate Transparency',
    status: ctIssue || pageFailures ? 'failed' : 'ok',
    detail,
    candidates: liveCandidates,
  };
}

export async function fetchItunesApps(brand: BrandProfile): Promise<SourceResult> {
  const endpoint = `https://itunes.apple.com/search?entity=software&limit=25&term=${encodeURIComponent(brand.name)}`;
  const response = await safeGet(endpoint, 1024 * 1024);
  const parsed = JSON.parse(response.body.toString('utf8')) as {
    results?: Array<{
      trackId?: number;
      trackName?: string;
      artistName?: string;
      description?: string;
      artworkUrl512?: string;
      artworkUrl100?: string;
      trackViewUrl?: string;
      bundleId?: string;
    }>;
  };
  const candidates = (parsed.results || []).flatMap((app): RadarCandidate[] => {
    if (!app.trackId || !app.trackName || !app.trackViewUrl) return [];
    const identifier = app.bundleId || String(app.trackId);
    return [{
      source: 'itunes_search',
      assetType: 'mobile_application',
      platform: 'apple_app_store',
      identifier,
      name: app.trackName,
      url: app.trackViewUrl,
      description: app.description || '',
      publisher: app.artistName,
      logoUrl: app.artworkUrl512 || app.artworkUrl100,
      payload: app,
    }];
  });
  return {
    name: 'Apple App Store (iTunes Search API)',
    status: 'ok',
    detail: `${candidates.length} records returned by the public iTunes Search API.`,
    candidates,
  };
}

export async function fetchGooglePlayApps(_brand: BrandProfile): Promise<SourceResult> {
  return {
    name: 'Google Play',
    status: 'skipped',
    detail: 'No supported Google Play search provider is configured; no results were fabricated.',
    candidates: [],
  };
}

export function socialDemoAdapter(findings: Finding[]): SourceAdapter {
  return {
    name: 'Existing social seed/ingest records',
    async fetchCandidates(): Promise<SourceResult> {
      const candidates = findings
        .filter((finding) => finding.isSimulated && finding.assetType === 'social_profile' && !finding.isOfficialAsset)
        .map((finding) => ({
          source: 'demo',
          assetType: finding.assetType,
          platform: finding.platform,
          identifier: finding.identifier,
          name: finding.candidateName,
          url: finding.url,
          description: finding.descriptionSnippet || '',
          publisher: finding.publisherOrDeveloper,
          logoUrl: finding.iconUrl || String(finding.candidatePayload.avatarUrl || ''),
          isDemo: true,
          payload: finding.candidatePayload,
        }));
      return {
        name: 'Existing social seed/ingest records',
        status: candidates.length ? 'ok' : 'skipped',
        detail: candidates.length
          ? `${candidates.length} existing demo records; labeled as demo and not represented as live intelligence.`
          : 'No existing demo social records are available.',
        candidates,
      };
    },
  };
}

export function socialApiPlaceholders(env: NodeJS.ProcessEnv = process.env): SourceAdapter {
  return {
    name: 'Social platform APIs',
    async fetchCandidates(): Promise<SourceResult> {
      const keys = ['X_BEARER_TOKEN', 'META_ACCESS_TOKEN', 'LINKEDIN_ACCESS_TOKEN'];
      const configured = keys.filter((key) => Boolean(env[key]));
      return {
        name: 'Social platform APIs',
        status: 'skipped',
        detail: configured.length
          ? 'Credentials are configured, but platform-specific API connectors are not implemented; no results were requested.'
          : `Not configured; optional credentials: ${keys.join(', ')}.`,
        candidates: [],
      };
    },
  };
}

export function defaultRadarAdapters(findings: Finding[]): SourceAdapter[] {
  const adapters: SourceAdapter[] = [
    { name: 'Lookalike domains + Certificate Transparency', fetchCandidates: fetchLookalikeDomains },
    { name: 'Apple App Store (iTunes Search API)', fetchCandidates: fetchItunesApps },
    { name: 'Google Play', fetchCandidates: fetchGooglePlayApps },
    socialDemoAdapter(findings),
    socialApiPlaceholders(),
  ];
  return adapters;
}

export async function collectSourceAdapters(
  brand: BrandProfile,
  adapters: SourceAdapter[],
): Promise<SourceResult[]> {
  return Promise.all(adapters.map(async (adapter) => {
    try {
      return await adapter.fetchCandidates(brand);
    } catch (error) {
      return {
        name: adapter.name,
        status: 'failed',
        detail: error instanceof Error ? error.message : 'Source adapter failed unexpectedly.',
        candidates: [],
      };
    }
  }));
}
