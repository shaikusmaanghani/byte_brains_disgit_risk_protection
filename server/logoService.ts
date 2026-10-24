import { Jimp } from 'jimp';
import type { BrandProfile, LogoComparison } from '../src/types/index.js';
import { AppStateModel } from './models.js';
import { safeGet } from './safeHttp.js';

interface LogoHash {
  url: string;
  pHash: string;
  dHash: string;
  histogram: number[];
}

const LOGO_MAX_BYTES = 2 * 1024 * 1024;
const LOGO_METHOD = 'pHash+dHash+color histogram' as const;

function grayscalePixels(data: Buffer, width: number, height: number): number[] {
  const result: number[] = [];
  for (let index = 0; index < width * height; index++) {
    const offset = index * 4;
    result.push(
      0.299 * data[offset] +
      0.587 * data[offset + 1] +
      0.114 * data[offset + 2],
    );
  }
  return result;
}

function toHex(bits: boolean[]): string {
  let value = 0n;
  for (const bit of bits) value = (value << 1n) | (bit ? 1n : 0n);
  return value.toString(16).padStart(16, '0');
}

function hammingDistance(left: string, right: string): number {
  let value = BigInt(`0x${left}`) ^ BigInt(`0x${right}`);
  let distance = 0;
  while (value) {
    distance++;
    value &= value - 1n;
  }
  return distance;
}

async function hashImage(buffer: Buffer, url: string): Promise<LogoHash> {
  const image = await Jimp.read(buffer);
  const phashImage = image.clone().resize({ w: 32, h: 32 });
  const pixels = grayscalePixels(phashImage.bitmap.data, 32, 32);
  const coefficients: number[] = [];
  for (let vertical = 0; vertical < 8; vertical++) {
    for (let horizontal = 0; horizontal < 8; horizontal++) {
      let total = 0;
      for (let y = 0; y < 32; y++) {
        const yWeight = Math.cos(((2 * y + 1) * vertical * Math.PI) / 64);
        for (let x = 0; x < 32; x++) {
          total += pixels[y * 32 + x] *
            Math.cos(((2 * x + 1) * horizontal * Math.PI) / 64) *
            yWeight;
        }
      }
      coefficients.push(total);
    }
  }
  const sorted = coefficients.slice(1).sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  const pHash = toHex(coefficients.map((value, index) => index > 0 && value >= median));

  const differenceImage = image.clone().resize({ w: 9, h: 8 });
  const differencePixels = grayscalePixels(differenceImage.bitmap.data, 9, 8);
  const dHashBits: boolean[] = [];
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      dHashBits.push(differencePixels[y * 9 + x] > differencePixels[y * 9 + x + 1]);
    }
  }

  const colorImage = image.clone().resize({ w: 32, h: 32 });
  const histogram = new Array<number>(64).fill(0);
  for (let index = 0; index < 32 * 32; index++) {
    const offset = index * 4;
    const bin =
      (colorImage.bitmap.data[offset] >> 6) * 16 +
      (colorImage.bitmap.data[offset + 1] >> 6) * 4 +
      (colorImage.bitmap.data[offset + 2] >> 6);
    histogram[bin]++;
  }
  const totalPixels = 32 * 32;
  return {
    url,
    pHash,
    dHash: toHex(dHashBits),
    histogram: histogram.map((count) => count / totalPixels),
  };
}

function compareHashes(official: LogoHash, candidate: LogoHash): LogoComparison {
  const pHashDistance = hammingDistance(official.pHash, candidate.pHash);
  const dHashDistance = hammingDistance(official.dHash, candidate.dHash);
  const colorDistance = official.histogram.reduce(
    (total, value, index) => total + Math.abs(value - candidate.histogram[index]),
    0,
  ) / 2;
  const colorHistogramSimilarity = Math.round((1 - colorDistance) * 100);
  const featureAgreement = (
    0.4 * (1 - pHashDistance / 64) +
    0.4 * (1 - dHashDistance / 64) +
    0.2 * (1 - colorDistance)
  ) * 100;
  const combined = Math.round((featureAgreement - 30) / 0.7);
  return {
    similarity: Math.max(0, Math.min(100, Math.round(combined))),
    method: LOGO_METHOD,
    pHashDistance,
    dHashDistance,
    colorHistogramSimilarity,
  };
}

async function fetchAndHash(url: string): Promise<{ hash?: LogoHash; reason?: string }> {
  try {
    const response = await safeGet(url, LOGO_MAX_BYTES);
    if (!response.contentType.startsWith('image/')) {
      return { reason: `Logo not available; remote content type was ${response.contentType || 'unspecified'}, not an image.` };
    }
    return { hash: await hashImage(response.body, response.url) };
  } catch (error) {
    return {
      reason: `Logo not available; ${error instanceof Error ? error.message : 'image request failed.'}`,
    };
  }
}

export async function officialLogoHashes(brand: BrandProfile): Promise<LogoHash[]> {
  const key = `officialLogoHashes:${brand.id}`;
  const urls = [brand.logoUrl, ...brand.officialApps.map((app) => app.iconUrl || '')]
    .filter((url) => /^https?:\/\//i.test(url));
  const existing = await AppStateModel.findOne({ key }).lean().exec();
  const cached = existing?.value as { urls?: string[]; hashes?: LogoHash[] } | undefined;
  if (cached?.hashes?.length && JSON.stringify(cached.urls) === JSON.stringify(urls)) {
    return cached.hashes;
  }
  const results = await Promise.all(urls.map(fetchAndHash));
  const hashes = results.flatMap((result) => result.hash ? [result.hash] : []);
  await AppStateModel.updateOne(
    { key },
    { $set: { value: { urls, hashes, updatedAt: new Date().toISOString() } } },
    { upsert: true },
  );
  return hashes;
}

export async function compareCandidateLogo(
  imageUrl: string | undefined,
  officialHashes: LogoHash[],
): Promise<{ comparison?: LogoComparison; reason?: string }> {
  if (!imageUrl) return { reason: 'Logo not available; no candidate image reference was supplied.' };
  if (!officialHashes.length) return { reason: 'Logo not available; no official logo image could be processed.' };
  const result = await fetchAndHash(imageUrl);
  if (!result.hash) return { reason: result.reason || 'Logo not available; candidate image could not be processed.' };
  const candidate = result.hash;
  return {
    comparison: officialHashes
      .map((official) => compareHashes(official, candidate))
      .sort((a, b) => b.similarity - a.similarity)[0],
  };
}

export async function compareImageBuffers(
  officialBuffer: Buffer,
  candidateBuffer: Buffer,
): Promise<LogoComparison> {
  const [official, candidate] = await Promise.all([
    hashImage(officialBuffer, 'official'),
    hashImage(candidateBuffer, 'candidate'),
  ]);
  return compareHashes(official, candidate);
}
