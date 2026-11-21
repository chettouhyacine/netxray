/**
 * Imports a HAR exported by any browser's DevTools (Chrome, Edge, Firefox,
 * Safari, …) and runs it through the same analyzer as live capture.
 *
 * This is what makes the four v1 checks useful outside Chromium: the DevTools
 * extension can only attach to a Chromium browser, but the analysis is plain
 * data in, plain findings out.
 */
import { normalizeHarEntry, type HarCookie, type HarEntry } from './har';
import type { CookieObservation, NetworkEvent } from './types';

interface HarRoot {
  log?: {
    entries?: HarEntry[];
    pages?: { title?: string }[];
  };
}

export interface HarImportResult {
  events: NetworkEvent[];
  cookies: CookieObservation[];
  pageUrl: string;
  /** Entries without a request URL are not usable and are counted here. */
  skipped: number;
}

function parseSameSite(value: string | undefined): CookieObservation['sameSite'] {
  const normalized = (value ?? '').trim().toLowerCase();
  if (normalized === 'none' || normalized === 'no_restriction') return 'no_restriction';
  if (normalized === 'strict') return 'strict';
  if (normalized === 'lax') return 'lax';
  return 'unspecified';
}

function cookieFromHar(cookie: HarCookie): CookieObservation | null {
  if (!cookie.name) return null;
  const expires = cookie.expires ? Date.parse(cookie.expires) : Number.NaN;
  const domain = cookie.domain ?? '';
  return {
    name: cookie.name,
    value: cookie.value ?? '',
    domain,
    path: cookie.path ?? '/',
    secure: Boolean(cookie.secure),
    httpOnly: Boolean(cookie.httpOnly),
    sameSite: parseSameSite(cookie.sameSite),
    session: !Number.isFinite(expires),
    expirationDate: Number.isFinite(expires) ? Math.floor(expires / 1000) : undefined,
    hostOnly: Boolean(domain) && !domain.startsWith('.'),
  };
}

function collectCookies(entries: HarEntry[]): CookieObservation[] {
  const seen = new Set<string>();
  const cookies: CookieObservation[] = [];
  for (const entry of entries) {
    for (const raw of entry.response?.cookies ?? []) {
      const cookie = cookieFromHar(raw);
      if (!cookie) continue;
      const key = `${cookie.name}@${cookie.domain}${cookie.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      cookies.push(cookie);
    }
  }
  return cookies;
}

/**
 * Parses HAR text. Throws a user-facing Error when the file is unusable;
 * individual entries that cannot be normalized are skipped, never guessed.
 */
export function importHar(text: string): HarImportResult {
  let parsed: HarRoot;
  try {
    parsed = JSON.parse(text) as HarRoot;
  } catch {
    throw new Error('That file is not valid JSON. Export a HAR from your browser DevTools and try again.');
  }

  const allEntries = parsed?.log?.entries;
  if (!Array.isArray(allEntries) || allEntries.length === 0) {
    throw new Error('No HAR entries found. Export the network log from DevTools, then import the .har file.');
  }

  const entries = allEntries.filter((entry) => Boolean(entry?.request?.url));
  if (entries.length === 0) {
    throw new Error('The HAR contains no requests with a URL.');
  }

  const documentUrl = entries.find((entry) => {
    const mime = (entry.response?.content?.mimeType ?? '').toLowerCase();
    return entry._resourceType === 'document' || mime.includes('text/html');
  })?.request.url;
  const pageUrl = documentUrl ?? entries[0]?.request.url ?? '';

  const startedTimes = entries
    .map((entry) => Date.parse(entry.startedDateTime))
    .filter((value) => Number.isFinite(value));
  const sessionStart = startedTimes.length > 0 ? Math.min(...startedTimes) : Date.now();

  const events: NetworkEvent[] = [];
  let skipped = allEntries.length - entries.length;
  entries.forEach((entry, index) => {
    try {
      events.push(
        normalizeHarEntry(entry, {
          pageUrl,
          sessionStart,
          sequence: index,
        }),
      );
    } catch {
      skipped += 1;
    }
  });

  if (events.length === 0) {
    throw new Error('The HAR entries could not be normalized. Try exporting again with response bodies included.');
  }

  events.sort((a, b) => a.startedAt - b.startedAt);
  return {
    events,
    cookies: collectCookies(entries),
    pageUrl,
    skipped,
  };
}
