import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import http from 'node:http';
import https from 'node:https';
import type { LookupAddress } from 'node:dns';
import type { LookupFunction } from 'node:net';

export interface SafeResponse {
  url: string;
  status: number;
  contentType: string;
  location?: string;
  body: Buffer;
}

const MAX_REDIRECTS = 3;

function ipv4Number(address: string): number | null {
  if (isIP(address) !== 4) return null;
  return address.split('.').reduce((value, part) => (value * 256) + Number(part), 0);
}

function ipv6Number(address: string): bigint | null {
  let value = address.toLowerCase().split('%')[0];
  const embeddedIpv4 = value.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (embeddedIpv4) {
    const ipv4 = ipv4Number(embeddedIpv4[1]);
    if (ipv4 === null) return null;
    const high = ((ipv4 >>> 16) & 0xffff).toString(16);
    const low = (ipv4 & 0xffff).toString(16);
    value = value.replace(embeddedIpv4[1], `${high}:${low}`);
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return null;
  return words.reduce((result, word) => (result << 16n) | BigInt(`0x${word}`), 0n);
}

function isPublicAddress(address: string): boolean {
  const normalized = address.toLowerCase().replace(/^\[|\]$/g, '');
  const family = isIP(normalized);
  if (family === 4) {
    const [a, b, c] = normalized.split('.').map(Number);
    return !(
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || (b === 0 && c === 0) || (b === 0 && c === 2))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)
    );
  }
  if (family === 6) {
    const value = ipv6Number(normalized);
    if (value === null || value === 0n || value === 1n) return false;
    const hex = value.toString(16).padStart(32, '0');
    if (hex.startsWith('00000000000000000000ffff')) {
      const ipv4 = Number(BigInt(`0x${hex.slice(24)}`));
      return isPublicAddress([
        (ipv4 >>> 24) & 255,
        (ipv4 >>> 16) & 255,
        (ipv4 >>> 8) & 255,
        ipv4 & 255,
      ].join('.'));
    }
    return (value >> 125n) === 1n &&
      !hex.startsWith('20010db8') &&
      !hex.startsWith('20010000') &&
      !hex.startsWith('20010002') &&
      !hex.startsWith('20010010') &&
      !hex.startsWith('20010020') &&
      !hex.startsWith('2002');
  }
  return false;
}

async function resolvePublicAddresses(hostname: string): Promise<LookupAddress[]> {
  const host = hostname.replace(/^\[|\]$/g, '');
  const family = isIP(host);
  let addresses: LookupAddress[];
  if (family) {
    addresses = [{ address: host, family } as LookupAddress];
  } else {
    let timer: NodeJS.Timeout | undefined;
    try {
      addresses = await Promise.race([
        lookup(host, { all: true, verbatim: true }),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('DNS lookup timed out.')), 5000);
          timer.unref();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error('Destination resolves to a private or invalid IP address.');
  }
  return addresses;
}

async function requestOnce(url: URL, maxBytes: number): Promise<SafeResponse> {
  const addresses = await resolvePublicAddresses(url.hostname);
  const pinnedLookup: LookupFunction = (_hostname, options, callback) => {
    if (options.all) callback(null, addresses);
    else callback(null, addresses[0].address, addresses[0].family);
  };
  const transport = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const request = transport.request(url, {
      method: 'GET',
      headers: { 'User-Agent': 'SentinelShield-Radar/1.0', Accept: '*/*' },
      lookup: pinnedLookup,
      timeout: 5000,
    }, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on('data', (chunk: Buffer) => {
        try {
          assertResponseSize(size + chunk.length, maxBytes);
        } catch {
          response.destroy(new Error('Response exceeded the configured size limit.'));
          return;
        }
        size += chunk.length;
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => resolve({
        url: url.toString(),
        status: response.statusCode || 0,
        contentType: String(response.headers['content-type'] || '').split(';')[0].trim().toLowerCase(),
        location: response.headers.location,
        body: Buffer.concat(chunks),
      }));
    });
    request.on('timeout', () => request.destroy(new Error('Request timed out.')));
    request.on('error', reject);
    request.end();
  });
}

export async function safeGet(input: string | URL, maxBytes: number): Promise<SafeResponse> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new Error('Response size limit must be a positive safe integer.');
  }
  let current = new URL(input);
  for (let redirects = 0; ; redirects++) {
    if (!['http:', 'https:'].includes(current.protocol) || current.username || current.password) {
      throw new Error('Only unauthenticated HTTP or HTTPS URLs are allowed.');
    }
    if (current.port && current.port !== '80' && current.port !== '443') {
      throw new Error('Nonstandard destination ports are not allowed.');
    }
    const response = await requestOnce(current, maxBytes);
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      if (response.status < 200 || response.status >= 300) throw new Error(`Remote request returned HTTP ${response.status}.`);
      return response;
    }
    if (redirects >= MAX_REDIRECTS) throw new Error('Too many redirects.');
    if (!response.location) throw new Error('Redirect response did not include a location.');
    current = new URL(response.location, current);
  }
}

export { isPublicAddress };

export function assertResponseSize(actualBytes: number, maxBytes: number): void {
  if (actualBytes > maxBytes) throw new Error('Response exceeded the configured size limit.');
}
