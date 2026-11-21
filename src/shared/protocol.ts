import type { CookieObservation, NetworkEvent, TlsDetails } from '../core/types';

/** localStorage/sessionStorage entry, value truncated to 500 characters. */
export interface StorageEntry {
  key: string;
  value: string;
  truncated: boolean;
}

export interface StorageSnapshot {
  origin: string;
  localStorage: StorageEntry[];
  sessionStorage: StorageEntry[];
}

export interface TlsStatus {
  supported: boolean;
  attached: boolean;
  urlCount: number;
  error?: string;
}

export interface SessionSnapshot {
  events: NetworkEvent[];
  savedAt: number;
}

/** Requests sent from the DevTools panel to the service worker. */
export type PanelRequest =
  | { type: 'PING' }
  | { type: 'CAPTURE_BATCH'; tabId: number; events: NetworkEvent[] }
  | { type: 'GET_SESSION'; tabId: number }
  | { type: 'CLEAR_SESSION'; tabId: number }
  | { type: 'GET_COOKIES'; url: string }
  | { type: 'READ_STORAGE'; tabId: number }
  | { type: 'TLS_STATUS'; tabId: number }
  | { type: 'TLS_ENABLE'; tabId: number }
  | { type: 'TLS_DISABLE'; tabId: number }
  | { type: 'TLS_LOOKUP'; urls: string[] };

export interface PanelResponseMap {
  PING: { ok: true };
  CAPTURE_BATCH: { stored: number };
  GET_SESSION: SessionSnapshot;
  CLEAR_SESSION: { cleared: true };
  GET_COOKIES: { cookies: CookieObservation[] };
  READ_STORAGE: { snapshot: StorageSnapshot | null; error?: string };
  TLS_STATUS: TlsStatus;
  TLS_ENABLE: TlsStatus;
  TLS_DISABLE: TlsStatus;
  TLS_LOOKUP: { byUrl: Record<string, TlsDetails> };
}

export type PanelResponse<T extends PanelRequest['type']> = PanelResponseMap[T];

/** Sends a request and resolves with the typed response. */
export async function sendMessage<T extends PanelRequest>(
  request: T,
): Promise<PanelResponse<T['type']>> {
  return (await chrome.runtime.sendMessage(request)) as PanelResponse<T['type']>;
}
