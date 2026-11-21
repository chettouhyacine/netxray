import { SEVERITY_ORDER } from './score';
import type { DomainSummary, NetworkEvent, SessionSummary, Severity } from './types';
import { hostOf, isThirdParty } from './url';

export function sessionBounds(events: NetworkEvent[]): { start: number; end: number } {
  if (events.length === 0) return { start: Date.now(), end: Date.now() };
  let start = Number.POSITIVE_INFINITY;
  let end = 0;
  for (const event of events) {
    start = Math.min(start, event.startedAt);
    end = Math.max(end, event.startedAt + event.timings.total);
  }
  return { start, end };
}

/** Recomputes `startOffset` so the waterfall is relative to the session start. */
export function withSessionOffsets(events: NetworkEvent[]): NetworkEvent[] {
  const { start } = sessionBounds(events);
  return events.map((event) => ({ ...event, startOffset: Math.max(0, event.startedAt - start) }));
}

export function summarizeSession(
  events: NetworkEvent[],
  worstSeverityByDomain: Map<string, Severity> = new Map(),
): SessionSummary {
  const bounds = sessionBounds(events);
  const domains = new Map<string, DomainSummary>();
  let totalBytes = 0;

  for (const event of events) {
    const host = hostOf(event.url) || '(unknown)';
    const bytes = event.sizes.total;
    totalBytes += bytes;
    const existing = domains.get(host);
    if (existing) {
      existing.requestCount += 1;
      existing.bytes += bytes;
    } else {
      domains.set(host, {
        host,
        isThirdParty: isThirdParty(event.url, event.pageOrigin),
        requestCount: 1,
        bytes,
        worstSeverity: worstSeverityByDomain.get(host) ?? null,
        exampleUrl: event.url,
      });
    }
    const reported = worstSeverityByDomain.get(host);
    const current = domains.get(host);
    if (reported && current) {
      if (!current.worstSeverity || SEVERITY_ORDER[reported] > SEVERITY_ORDER[current.worstSeverity]) {
        current.worstSeverity = reported;
      }
    }
  }

  return {
    pageUrl: events.find((event) => event.resourceType === 'document')?.url ?? events[0]?.pageUrl ?? '',
    startedAt: bounds.start,
    endedAt: bounds.end,
    requestCount: events.length,
    totalBytes,
    domains: Array.from(domains.values()).sort((a, b) => b.bytes - a.bytes),
  };
}

/** Groups events by host for the map view. */
export function groupByDomain(events: NetworkEvent[]): Map<string, NetworkEvent[]> {
  const groups = new Map<string, NetworkEvent[]>();
  for (const event of events) {
    const host = hostOf(event.url) || '(unknown)';
    const list = groups.get(host) ?? [];
    list.push(event);
    groups.set(host, list);
  }
  return groups;
}

/**
 * Exports captured events as a HAR 1.2 document. Bodies are included only when
 * they were captured; nothing is fetched or reconstructed.
 */
export function exportHar(events: NetworkEvent[], pageUrl: string): string {
  const har = {
    log: {
      version: '1.2',
      creator: { name: 'NetXRay', version: '0.2.0' },
      pages: [
        {
          startedDateTime: new Date(events[0]?.startedAt ?? Date.now()).toISOString(),
          id: 'page_1',
          title: pageUrl,
          pageTimings: {},
        },
      ],
      entries: events.map((event) => ({
        startedDateTime: new Date(event.startedAt).toISOString(),
        time: event.timings.total,
        request: {
          method: event.method,
          url: event.url,
          httpVersion: event.httpVersion ?? 'HTTP/1.1',
          headers: Object.entries(event.requestHeaders).map(([name, value]) => ({ name, value })),
          queryString: Object.entries(event.query).flatMap(([name, values]) =>
            values.map((value) => ({ name, value })),
          ),
          cookies: event.requestCookies.map((cookie) => ({
            name: cookie.name,
            value: cookie.value,
          })),
          headersSize: event.sizes.requestHeaders,
          bodySize: event.sizes.requestBody,
          ...(event.requestBodyText
            ? { postData: { mimeType: event.requestHeaders['content-type'] ?? '', text: event.requestBodyText } }
            : {}),
        },
        response: {
          status: event.status,
          statusText: event.statusText,
          httpVersion: event.httpVersion ?? 'HTTP/1.1',
          headers: Object.entries(event.responseHeaders).map(([name, value]) => ({ name, value })),
          cookies: [],
          content: {
            size: event.sizes.responseBody,
            mimeType: event.mimeType,
            ...(event.responseBodyText ? { text: event.responseBodyText } : {}),
          },
          redirectURL: event.responseHeaders.location ?? '',
          headersSize: event.sizes.responseHeaders,
          bodySize: event.sizes.responseBody,
        },
        cache: {},
        timings: {
          blocked: event.timings.blocked,
          dns: event.timings.dns,
          connect: event.timings.tcp + event.timings.tls,
          ssl: event.timings.tls,
          send: event.timings.request,
          wait: event.timings.wait,
          receive: event.timings.download,
        },
        serverIPAddress: event.serverIpAddress ?? '',
        connection: '',
        pageref: 'page_1',
        _resourceType: event.resourceType,
        _netxray: {
          id: event.id,
          protocol: event.protocol,
          tls: event.tls,
          cookiesObserved: event.cookiesObserved,
        },
      })),
    },
  };
  return JSON.stringify(har, null, 2);
}
