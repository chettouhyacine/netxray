/**
 * NetXRay background service worker.
 *
 * Responsibilities:
 *  - persist the captured session per inspected tab (chrome.storage.session)
 *  - read cookies for a URL (chrome.cookies)
 *  - read localStorage/sessionStorage on explicit user request (chrome.scripting)
 *  - optional deep TLS inspection through chrome.debugger (opt-in permission)
 *
 * All data stays on this machine. The worker never performs its own network
 * requests and never evaluates page content.
 */
import type { CookieObservation, NetworkEvent, TlsDetails } from '../core/types';
import type { PanelRequest, SessionSnapshot, StorageSnapshot, TlsStatus } from '../shared/protocol';

const SESSION_PREFIX = 'nx:session:';
const TLS_PREFIX = 'nx:tls:';
const MAX_EVENTS = 1200;

/** Bodies are dropped from persisted snapshots to stay inside session quota. */
function slimEvent(event: NetworkEvent): NetworkEvent {
  return {
    ...event,
    responseBodyText: undefined,
    requestBodyText: undefined,
    bodyCaptured: false,
    responseBodyTruncated: undefined,
  };
}

async function readSession(tabId: number): Promise<SessionSnapshot> {
  const key = `${SESSION_PREFIX}${tabId}`;
  const stored = await chrome.storage.session.get(key);
  return (stored[key] as SessionSnapshot | undefined) ?? { events: [], savedAt: 0 };
}

async function writeSession(tabId: number, events: NetworkEvent[]): Promise<number> {
  const trimmed = events.slice(-MAX_EVENTS).map(slimEvent);
  const snapshot: SessionSnapshot = { events: trimmed, savedAt: Date.now() };
  await chrome.storage.session.set({ [`${SESSION_PREFIX}${tabId}`]: snapshot });
  return trimmed.length;
}

function normalizeCookie(cookie: chrome.cookies.Cookie): CookieObservation {
  return {
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain,
    path: cookie.path,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
    session: cookie.session,
    expirationDate: cookie.expirationDate,
    hostOnly: cookie.hostOnly,
    storeId: cookie.storeId,
  };
}

async function readCookies(url: string): Promise<CookieObservation[]> {
  try {
    const cookies = await chrome.cookies.getAll({ url });
    return cookies.map(normalizeCookie);
  } catch {
    return [];
  }
}

/** Runs in the inspected page (isolated world). Never calls eval. */
function readWebStorage(): StorageSnapshot {
  const dump = (storage: Storage) => {
    const entries: { key: string; value: string; truncated: boolean }[] = [];
    for (let index = 0; index < storage.length && entries.length < 200; index += 1) {
      const key = storage.key(index);
      if (key === null) continue;
      const value = storage.getItem(key) ?? '';
      entries.push({
        key,
        value: value.length > 500 ? value.slice(0, 500) : value,
        truncated: value.length > 500,
      });
    }
    return entries;
  };
  return {
    origin: location.origin,
    localStorage: dump(localStorage),
    sessionStorage: dump(sessionStorage),
  };
}

async function readStorage(tabId: number): Promise<{ snapshot: StorageSnapshot | null; error?: string }> {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: readWebStorage,
    });
    const snapshot = results[0]?.result;
    if (!snapshot) return { snapshot: null, error: 'The page returned no storage data.' };
    return { snapshot };
  } catch (error) {
    return {
      snapshot: null,
      error: error instanceof Error ? error.message : 'Could not read storage for this tab.',
    };
  }
}

// ---------------------------------------------------------------------------
// Deep TLS inspection (optional permission: "debugger")
// ---------------------------------------------------------------------------

const tlsState = new Map<number, Map<string, TlsDetails>>();
const tlsSaveTimers = new Map<number, ReturnType<typeof setTimeout>>();

function tlsKey(tabId: number): string {
  return `${TLS_PREFIX}${tabId}`;
}

async function loadTls(tabId: number): Promise<Map<string, TlsDetails>> {
  const cached = tlsState.get(tabId);
  if (cached) return cached;
  const key = tlsKey(tabId);
  const stored = await chrome.storage.session.get(key);
  const raw = (stored[key] as Record<string, TlsDetails> | undefined) ?? {};
  const map = new Map(Object.entries(raw));
  tlsState.set(tabId, map);
  return map;
}

function scheduleTlsSave(tabId: number): void {
  if (tlsSaveTimers.has(tabId)) return;
  tlsSaveTimers.set(
    tabId,
    setTimeout(() => {
      tlsSaveTimers.delete(tabId);
      const map = tlsState.get(tabId);
      if (!map) return;
      const record = Object.fromEntries(map);
      void chrome.storage.session.set({ [tlsKey(tabId)]: record });
    }, 500),
  );
}

async function tlsStatus(tabId: number): Promise<TlsStatus> {
  const supported = await chrome.permissions.contains({ permissions: ['debugger'] });
  let attached = false;
  if (supported && chrome.debugger?.getTargets) {
    try {
      const targets = await chrome.debugger.getTargets();
      attached = targets.some((target) => target.tabId === tabId && target.attached);
    } catch {
      attached = false;
    }
  }
  const map = await loadTls(tabId);
  return { supported, attached, urlCount: map.size };
}

async function enableTls(tabId: number): Promise<TlsStatus> {
  const granted = await chrome.permissions.contains({ permissions: ['debugger'] });
  bindDebuggerListeners();
  if (!granted) {
    return {
      supported: false,
      attached: false,
      urlCount: 0,
      error: 'The debugger permission was not granted.',
    };
  }
  try {
    const targets = await chrome.debugger.getTargets();
    const already = targets.some((target) => target.tabId === tabId && target.attached);
    if (!already) {
      await chrome.debugger.attach({ tabId }, '1.3');
    }
    await chrome.debugger.sendCommand({ tabId }, 'Network.enable', {});
    return tlsStatus(tabId);
  } catch (error) {
    return {
      supported: true,
      attached: false,
      urlCount: 0,
      error: error instanceof Error ? error.message : 'Could not attach the debugger.',
    };
  }
}

async function disableTls(tabId: number): Promise<TlsStatus> {
  try {
    await chrome.debugger.sendCommand({ tabId }, 'Network.disable', {});
  } catch {
    // ignore: target may already be gone
  }
  try {
    await chrome.debugger.detach({ tabId });
  } catch {
    // ignore: not attached
  }
  tlsState.delete(tabId);
  await chrome.storage.session.remove(tlsKey(tabId));
  return tlsStatus(tabId);
}

/** Subset of the CDP Network.SecurityDetails payload we consume. */
interface CdpSecurityDetails {
  protocol?: string;
  cipher?: string;
  keyExchange?: string;
  subjectName?: string;
  issuer?: string;
  validFrom?: number;
  validTo?: number;
  sanList?: string[];
}

/** Maps CDP securityDetails onto our compact TLS model. */
function toTlsDetails(details: CdpSecurityDetails): TlsDetails {
  const protocolName = details.protocol ?? '';
  return {
    protocol: protocolName,
    cipher: details.cipher ?? undefined,
    keyExchange: details.keyExchange ?? undefined,
    certificate: {
      subjectName: details.subjectName ?? undefined,
      issuer: details.issuer ?? undefined,
      validFrom: details.validFrom,
      validTo: details.validTo,
      sanList: details.sanList ?? undefined,
    },
  };
}

let debuggerListenersBound = false;

/**
 * The chrome.debugger namespace only exists once the optional permission is
 * granted. Accessing it unconditionally at module scope used to abort the whole
 * worker before the message listener below was registered.
 */
function bindDebuggerListeners(): void {
  if (debuggerListenersBound || !chrome.debugger?.onEvent) return;
  debuggerListenersBound = true;

  chrome.debugger.onEvent.addListener((source, method, params) => {
    if (method !== 'Network.responseReceived' || source.tabId === undefined) return;
    const payload = params as { response?: { url?: string; securityDetails?: CdpSecurityDetails } };
    const response = payload.response;
    if (!response?.url || !response.securityDetails) return;
    const tabId = source.tabId;
    const map = tlsState.get(tabId) ?? new Map<string, TlsDetails>();
    map.set(response.url, toTlsDetails(response.securityDetails));
    tlsState.set(tabId, map);
    scheduleTlsSave(tabId);
  });

  chrome.debugger.onDetach.addListener((source) => {
    if (source.tabId === undefined) return;
    tlsState.delete(source.tabId);
    void chrome.storage.session.remove(tlsKey(source.tabId));
  });
}

bindDebuggerListeners();

// ---------------------------------------------------------------------------
// Message router
// ---------------------------------------------------------------------------

async function handle(request: PanelRequest): Promise<unknown> {
  switch (request.type) {
    case 'PING':
      return { ok: true };
    case 'CAPTURE_BATCH': {
      const stored = await writeSession(request.tabId, request.events);
      return { stored };
    }
    case 'GET_SESSION':
      return readSession(request.tabId);
    case 'CLEAR_SESSION':
      await chrome.storage.session.remove(`${SESSION_PREFIX}${request.tabId}`);
      return { cleared: true };
    case 'GET_COOKIES':
      return { cookies: await readCookies(request.url) };
    case 'READ_STORAGE':
      return readStorage(request.tabId);
    case 'TLS_STATUS':
      return tlsStatus(request.tabId);
    case 'TLS_ENABLE':
      return enableTls(request.tabId);
    case 'TLS_DISABLE':
      return disableTls(request.tabId);
    case 'TLS_LOOKUP': {
      const wanted = new Set(request.urls);
      const byUrl: Record<string, TlsDetails> = {};
      for (const [tabId, map] of tlsState) {
        for (const [url, details] of map) {
          if (wanted.has(url)) byUrl[url] = details;
        }
        void tabId;
      }
      return { byUrl };
    }
    default:
      return { error: 'Unknown request' };
  }
}

chrome.runtime.onMessage.addListener((message: PanelRequest, _sender, sendResponse) => {
  handle(message)
    .then(sendResponse)
    .catch((error: unknown) => {
      sendResponse({ error: error instanceof Error ? error.message : 'Background error' });
    });
  return true;
});

// Keep the worker module side-effect free beyond listener registration: the
// listeners above wake it for debugger events even after Chrome stops it.
