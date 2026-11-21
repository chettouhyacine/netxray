/**
 * Shared domain model for NetXRay.
 *
 * Everything captured from the browser is normalized into a `NetworkEvent`
 * before analysis or rendering. The model is intentionally plain data: no
 * class instances, no functions, safe to post to/from Web Workers and
 * chrome.storage.
 */
import type { AttackClass, Confidence } from './attacks';
import type { PhaseTimings } from './phases';

export type Severity = 'info' | 'low' | 'medium' | 'high';

export interface HeaderEntry {
  name: string;
  value: string;
}

export interface HarTimings {
  blocked?: number;
  dns?: number;
  connect?: number;
  ssl?: number;
  send?: number;
  wait?: number;
  receive?: number;
}

/** Raw cookie as observed in `Cookie` / `Set-Cookie` headers. */
export interface RawCookie {
  name: string;
  value: string;
  /** Parsed Set-Cookie attributes (empty for request cookies). */
  attributes: Record<string, string | true>;
}

/** Cookie attributes as reported by the chrome.cookies API. */
export interface CookieObservation {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  /** `unspecified` when the cookie predates SameSite or the attribute is absent. */
  sameSite: 'no_restriction' | 'lax' | 'strict' | 'unspecified';
  session: boolean;
  expirationDate?: number;
  hostOnly: boolean;
  storeId?: string;
}

/** TLS details obtained through chrome.debugger (Network.securityDetails). */
export interface TlsDetails {
  protocol?: string;
  cipher?: string;
  keyExchange?: string;
  certificate?: {
    subjectName?: string;
    issuer?: string;
    validFrom?: number;
    validTo?: number;
    sanList?: string[];
  };
}

export interface SizeInfo {
  requestHeaders: number;
  requestBody: number;
  responseHeaders: number;
  responseBody: number;
  total: number;
}

/** Values injected by the intercepting layer (response body, cookies, TLS). */
export interface EventExtras {
  responseBodyText?: string;
  responseBodyTruncated?: boolean;
  requestBodyText?: string;
  cookiesObserved?: CookieObservation[];
  tls?: TlsDetails;
}

export interface NetworkEvent {
  /** Stable id derived from start time + url + method. */
  id: string;
  /** Epoch milliseconds when the request started. */
  startedAt: number;
  /** Milliseconds since the first captured request of the session. */
  startOffset: number;
  url: string;
  /** Origin of the page being inspected at capture time. */
  pageUrl: string;
  pageOrigin: string;
  method: string;
  status: number;
  statusText: string;
  mimeType: string;
  /** HAR `_resourceType`: document, script, stylesheet, xhr, ... */
  resourceType: string;
  protocol?: string;
  httpVersion?: string;
  serverIpAddress?: string;
  connectionReused?: boolean;
  fromCache: boolean;
  cacheControl?: string;
  initiator?: string;
  /** Lower-cased header map; repeated headers are comma-joined. */
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
  /** All values of Set-Cookie, unparsed, in order. */
  setCookie: string[];
  requestCookies: RawCookie[];
  query: Record<string, string[]>;
  sizes: SizeInfo;
  timings: PhaseTimings;
  bodyCaptured: boolean;
  responseBodyText?: string;
  responseBodyTruncated?: boolean;
  requestBodyText?: string;
  cookiesObserved: CookieObservation[];
  tls?: TlsDetails;
}

export interface Finding {
  /** Unique per rule + affected object, used for de-duplication. */
  id: string;
  ruleId: string;
  severity: Severity;
  title: string;
  what: string;
  why: string;
  attack: string;
  remediation: Remediation[];
  message: string;
  detail?: string;
  evidence?: string;
  eventId?: string;
  url?: string;
  domain?: string;
  tags: string[];
  /** One of the four v1 attack classes, or undefined for extended checks. */
  attackClass?: AttackClass;
  /** How strong the evidence is that this is a real, exploitable issue. */
  confidence: Confidence;
  /** Number of requests that produced this same finding. */
  occurrences?: number;
}

export interface Remediation {
  framework: 'express' | 'nextjs' | 'nginx' | 'generic';
  language?: string;
  code: string;
  note?: string;
}

export interface PageContext {
  pageUrl: string;
  pageOrigin: string;
  isHttps: boolean;
}

export interface SessionSummary {
  pageUrl: string;
  startedAt: number;
  endedAt: number;
  requestCount: number;
  totalBytes: number;
  domains: DomainSummary[];
}

export interface DomainSummary {
  host: string;
  isThirdParty: boolean;
  requestCount: number;
  bytes: number;
  worstSeverity: Severity | null;
  exampleUrl: string;
}

export interface ScoreResult {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  counts: Record<Severity, number>;
}
