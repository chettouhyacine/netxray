import { collectSetCookies, headerMap, parseRequestCookies, parseSetCookie } from './headers';
import { normalizeTimings } from './timings';
import type { HarTimings, HeaderEntry, NetworkEvent, RawCookie } from './types';

/** Cookie as recorded in a HAR `response.cookies` array. */
export interface HarCookie {
  name?: string;
  value?: string;
  domain?: string;
  path?: string;
  expires?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
}

/** Structural subset of a HAR entry produced by chrome.devtools.network. */
export interface HarEntry {
  startedDateTime: string;
  time?: number;
  request: {
    method: string;
    url: string;
    httpVersion?: string;
    headers?: HeaderEntry[];
    postData?: { mimeType?: string; text?: string };
    headersSize?: number;
    bodySize?: number;
  };
  response: {
    status: number;
    statusText?: string;
    headers?: HeaderEntry[];
    content?: { size?: number; mimeType?: string; text?: string; encoding?: string };
    cookies?: HarCookie[];
    headersSize?: number;
    bodySize?: number;
    _transferSize?: number;
  };
  cache?: { beforeRequest?: unknown; afterRequest?: unknown };
  timings?: HarTimings;
  serverIPAddress?: string;
  /** Chrome sometimes exposes the IP under the underscore-prefixed key. */
  _serverIPAddress?: string;
  connection?: string;
  pageref?: string;
  _resourceType?: string;
  _initiator?: { type?: string; url?: string; stack?: { callFrames?: { url?: string }[] } };
}

const MAX_BODY_CHARS = 256 * 1024;

function decodeBody(content: { text?: string; encoding?: string } | undefined): string | undefined {
  if (!content?.text) return undefined;
  if (content.encoding !== 'base64') return content.text.slice(0, MAX_BODY_CHARS);
  try {
    const binary =
      typeof atob === 'function'
        ? atob(content.text)
        : Buffer.from(content.text, 'base64').toString('binary');
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes).slice(0, MAX_BODY_CHARS);
  } catch {
    return undefined;
  }
}

function queryMap(url: string): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  try {
    for (const [key, value] of new URL(url).searchParams.entries()) {
      (result[key] ??= []).push(value);
    }
  } catch {
    // ignore malformed URLs; they are still shown as text
  }
  return result;
}

function initiatorOf(entry: HarEntry): string | undefined {
  if (entry._initiator?.url) return entry._initiator.url;
  const frameUrl = entry._initiator?.stack?.callFrames?.[0]?.url;
  return frameUrl;
}

function safeSize(value: number | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : 0;
}

function cacheControlOf(headers: Record<string, string>): string | undefined {
  return headers['cache-control'];
}

function pageOriginOf(pageUrl: string): string {
  try {
    return new URL(pageUrl).origin;
  } catch {
    return '';
  }
}

export interface NormalizeOptions {
  /** URL of the inspected page when the request was captured. */
  pageUrl: string;
  /** Session start in epoch ms, used to compute the waterfall offset. */
  sessionStart?: number;
  /** Disambiguates identical requests captured in the same millisecond. */
  sequence?: number;
  requestBodyText?: string;
  responseBodyText?: string;
  responseBodyTruncated?: boolean;
}

/**
 * Live DevTools entries occasionally omit `_resourceType`. Infer it from the
 * response MIME type so document-only rules and page-origin tracking still work.
 */
export function inferResourceType(entry: HarEntry): string {
  if (entry._resourceType) return entry._resourceType;
  const mime = (entry.response?.content?.mimeType ?? '').toLowerCase();
  if (mime.includes('text/html') || mime.includes('application/xhtml')) return 'document';
  if (mime.includes('text/css')) return 'stylesheet';
  if (mime.includes('javascript') || mime.includes('ecmascript')) return 'script';
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('font/') || mime.includes('woff') || mime.includes('ttf')) return 'font';
  if (mime.startsWith('audio/') || mime.startsWith('video/')) return 'media';
  if (mime.includes('json') || mime.includes('xml') || mime.includes('graphql')) return 'xhr';
  return 'other';
}

/**
 * Converts one HAR entry into the normalized event model.
 * Throws only when the entry has no usable URL.
 */
export function normalizeHarEntry(entry: HarEntry, options: NormalizeOptions): NetworkEvent {
  if (!entry?.request?.url) throw new Error('HAR entry without request URL');
  const startedAt = Date.parse(entry.startedDateTime);
  const started = Number.isFinite(startedAt) ? startedAt : Date.now();
  const requestHeaders = headerMap(entry.request.headers);
  const responseHeaders = headerMap(entry.response.headers);
  const setCookieRaw = collectSetCookies(entry.response.headers);
  const requestCookies: RawCookie[] = parseRequestCookies(requestHeaders.cookie);
  const responseBody =
    options.responseBodyText ?? decodeBody(entry.response.content);
  const truncated =
    options.responseBodyTruncated ??
    (entry.response.content?.text ? entry.response.content.text.length > MAX_BODY_CHARS : false);
  const requestBody =
    options.requestBodyText ?? entry.request.postData?.text ?? undefined;

  const sizes = {
    requestHeaders: safeSize(entry.request.headersSize),
    requestBody: safeSize(entry.request.bodySize),
    responseHeaders: safeSize(entry.response.headersSize),
    responseBody: safeSize(entry.response.content?.size ?? entry.response.bodySize),
    total: 0,
  };
  sizes.total =
    sizes.requestHeaders +
    sizes.requestBody +
    sizes.responseHeaders +
    sizes.responseBody;

  const timings = normalizeTimings(entry.timings);
  const pageOrigin = pageOriginOf(options.pageUrl);
  const id = `${started}-${entry.request.method}-${entry.request.url}-${options.sequence ?? 0}`;

  return {
    id,
    startedAt: started,
    startOffset: Math.max(0, started - (options.sessionStart ?? started)),
    url: entry.request.url,
    pageUrl: options.pageUrl,
    pageOrigin,
    method: entry.request.method.toUpperCase(),
    status: entry.response.status ?? 0,
    statusText: entry.response.statusText ?? '',
    mimeType: entry.response.content?.mimeType ?? '',
    resourceType: inferResourceType(entry),
    protocol: undefined,
    httpVersion: entry.request.httpVersion,
    serverIpAddress: entry.serverIPAddress ?? entry._serverIPAddress,
    connectionReused: false,
    fromCache: Boolean(entry.cache?.beforeRequest),
    cacheControl: cacheControlOf(responseHeaders),
    initiator: initiatorOf(entry),
    requestHeaders,
    responseHeaders,
    setCookie: setCookieRaw,
    requestCookies,
    query: queryMap(entry.request.url),
    sizes,
    timings,
    bodyCaptured: Boolean(responseBody),
    responseBodyText: responseBody,
    responseBodyTruncated: truncated || undefined,
    requestBodyText: requestBody,
    cookiesObserved: [],
  };
}

/** Parses raw Set-Cookie strings, exposed for the storage/cookie view. */
export function parsedSetCookies(event: NetworkEvent): RawCookie[] {
  return event.setCookie.map(parseSetCookie);
}

/** True when the response looks textual enough to scan. */
export function isTextualMime(mimeType: string): boolean {
  const mime = mimeType.toLowerCase();
  return (
    mime.startsWith('text/') ||
    mime.includes('json') ||
    mime.includes('xml') ||
    mime.includes('javascript') ||
    mime.includes('graphql')
  );
}
