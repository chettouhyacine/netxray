import { normalizeHarEntry, type HarEntry } from '../../core/har';
import type { NetworkEvent } from '../../core/types';

const MAX_BODY_CHARS = 256 * 1024;

export function hasDevtoolsApi(): boolean {
  return (
    typeof chrome !== 'undefined' &&
    typeof chrome.devtools !== 'undefined' &&
    typeof chrome.devtools.network !== 'undefined'
  );
}

export function inspectedTabId(): number | null {
  if (!hasDevtoolsApi()) return null;
  const tabId = chrome.devtools.inspectedWindow.tabId;
  return typeof tabId === 'number' ? tabId : null;
}

function readContent(entry: chrome.devtools.network.Request): Promise<{ text: string; truncated: boolean } | null> {
  return new Promise((resolve) => {
    try {
      entry.getContent((content, encoding) => {
        if (!content) return resolve(null);
        if (encoding === 'base64') {
          try {
            const binary = atob(content);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
            const decoded = new TextDecoder().decode(bytes);
            resolve({
              text: decoded.slice(0, MAX_BODY_CHARS),
              truncated: decoded.length > MAX_BODY_CHARS,
            });
            return;
          } catch {
            return resolve(null);
          }
        }
        resolve({ text: content.slice(0, MAX_BODY_CHARS), truncated: content.length > MAX_BODY_CHARS });
      });
    } catch {
      resolve(null);
    }
  });
}

export interface CaptureOptions {
  /**
   * Read at request time (not subscription time) so the body toggle can change
   * without dropping the DevTools listener.
   */
  shouldCaptureBodies: () => boolean;
  onEvent: (event: NetworkEvent) => void;
  onError?: (error: unknown) => void;
}

/**
 * Subscribes to DevTools' request stream. Each request becomes one normalized
 * NetworkEvent. `getContent` is best-effort: cached and streaming responses may
 * have no body, which is normal.
 */
export function startCapture(options: CaptureOptions): () => void {
  if (!hasDevtoolsApi()) return () => undefined;
  let sequence = 0;
  let pageUrl = '';
  let sessionStart = 0;

  const listener = (request: chrome.devtools.network.Request) => {
    const entry = request as unknown as HarEntry & chrome.devtools.network.Request;
    const url = entry.request?.url ?? '';
    if (!url || url.startsWith('data:') || url.startsWith('chrome-extension://')) return;
    const resourceType = entry._resourceType ?? 'other';
    if (!pageUrl || resourceType === 'document') {
      pageUrl = resourceType === 'document' ? url : pageUrl || url;
    }
    if (sessionStart === 0) sessionStart = Date.now();

    const capture = async (): Promise<void> => {
      let body: { text: string; truncated: boolean } | null = null;
      const mime = entry.response?.content?.mimeType ?? '';
      const textual = /text\/|json|xml|javascript|graphql/i.test(mime);
      if (options.shouldCaptureBodies() && textual && entry.response?.status !== 304) {
        body = await readContent(request);
      }
      const event = normalizeHarEntry(entry, {
        pageUrl,
        sessionStart,
        sequence: (sequence += 1),
        responseBodyText: body?.text,
        responseBodyTruncated: body?.truncated,
      });
      // DevTools gives the request HTTP version but not the TLS protocol.
      event.protocol = entry.request.httpVersion;
      options.onEvent(event);
    };

    capture().catch((error: unknown) => options.onError?.(error));
  };

  chrome.devtools.network.onRequestFinished.addListener(listener);
  return () => chrome.devtools.network.onRequestFinished.removeListener(listener);
}
