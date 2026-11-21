import { useEffect } from 'react';
import { sendMessage } from '../../shared/protocol';
import { usePanelStore } from '../store';
import { hasDevtoolsApi, inspectedTabId, startCapture } from './capture';

/**
 * Owns the capture lifecycle:
 *  - restores the persisted session for this tab
 *  - streams new requests into the store
 *  - persists batches to the service worker (debounced)
 *  - refreshes cookies for the inspected origin on document loads
 *  - merges deep-TLS details while the debugger is attached
 */
export function useSession(): void {
  useEffect(() => {
    const tabId = inspectedTabId();
    if (tabId === null) {
      usePanelStore
        .getState()
        .setNotice('Open NetXRay from DevTools (⋮ → More tools → NetXRay) to capture requests.');
      return;
    }

    let cancelled = false;
    let persistTimer: ReturnType<typeof setTimeout> | null = null;
    let documentUrl = '';

    const persist = (immediate = false) => {
      if (persistTimer) clearTimeout(persistTimer);
      const run = () => {
        persistTimer = null;
        const events = usePanelStore.getState().events;
        void sendMessage({ type: 'CAPTURE_BATCH', tabId, events }).catch(() => undefined);
      };
      if (immediate) run();
      else persistTimer = setTimeout(run, 700);
    };

    const hydrate = async () => {
      try {
        const snapshot = await sendMessage({ type: 'GET_SESSION', tabId });
        if (cancelled || snapshot.events.length === 0) return;
        usePanelStore.getState().addEvents(snapshot.events);
        const document_ = [...snapshot.events].reverse().find((event) => event.resourceType === 'document');
        if (document_) {
          documentUrl = document_.url;
          const cookies = await sendMessage({ type: 'GET_COOKIES', url: document_.url });
          if (!cancelled) usePanelStore.getState().setCookies(cookies.cookies);
        }
      } catch {
        // A missing snapshot is normal on first open.
      }
    };
    void hydrate();

    const stop = startCapture({
      shouldCaptureBodies: () => usePanelStore.getState().captureBodies,
      onEvent: (event) => {
        if (cancelled) return;
        const store = usePanelStore.getState();
        store.addEvents([event]);
        if (event.resourceType === 'document' && event.url !== documentUrl) {
          documentUrl = event.url;
          void sendMessage({ type: 'GET_COOKIES', url: event.url })
            .then((response) => {
              if (cancelled) return;
              usePanelStore.getState().setCookies(response.cookies);
              usePanelStore.getState().mergeEvent({ ...event, cookiesObserved: response.cookies });
            })
            .catch(() => undefined);
        }
        persist();
      },
      onError: () => usePanelStore.getState().setNotice('A request could not be normalized; it was skipped.'),
    });

    let onNavigated: (() => void) | null = null;
    if (hasDevtoolsApi()) {
      onNavigated = () => {
        documentUrl = '';
        usePanelStore.getState().clearSession();
        void sendMessage({ type: 'CLEAR_SESSION', tabId }).catch(() => undefined);
      };
      chrome.devtools.network.onNavigated.addListener(onNavigated);
    }

    void sendMessage({ type: 'TLS_STATUS', tabId })
      .then((status) => {
        if (!cancelled) usePanelStore.getState().setTls(status);
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
      stop();
      if (persistTimer) clearTimeout(persistTimer);
      // Flush the last batch so a closed panel does not lose recent requests.
      const events = usePanelStore.getState().events;
      void sendMessage({ type: 'CAPTURE_BATCH', tabId, events }).catch(() => undefined);
      if (onNavigated) chrome.devtools.network.onNavigated.removeListener(onNavigated);
    };
  }, []);

  // Rebuild the offset base when the session is cleared by navigation.
  const eventCount = usePanelStore((state) => state.events.length);
  useEffect(() => {
    if (eventCount === 0) return;
    const events = usePanelStore.getState().events;
    const first = events[0];
    if (!first || first.startOffset === 0) return;
    const rebased = events.map((event) => ({
      ...event,
      // Captures are relative to the first captured request of the session.
      startOffset: Math.max(0, event.startedAt - first.startedAt),
    }));
    usePanelStore.setState({ events: rebased });
  }, [eventCount]);

  // Poll for TLS details while the debugger is attached (opt-in only).
  const tlsAttached = usePanelStore((state) => state.tls.attached);
  useEffect(() => {
    if (!tlsAttached) return;
    let cancelled = false;
    const poll = async () => {
      const events = usePanelStore.getState().events.filter((event) => !event.tls);
      if (events.length === 0) return;
      const urls = Array.from(new Set(events.map((event) => event.url))).slice(0, 100);
      try {
        const response = await sendMessage({ type: 'TLS_LOOKUP', urls });
        if (cancelled) return;
        if (Object.keys(response.byUrl).length > 0) {
          usePanelStore.getState().applyTls(response.byUrl);
        }
      } catch {
        // ignore transient worker restarts
      }
    };
    void poll();
    const interval = setInterval(() => void poll(), 2500);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [tlsAttached]);
}
