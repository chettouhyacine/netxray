/** Phase names in the order a request moves through the network stack. */
export const PHASES = [
  'blocked',
  'dns',
  'tcp',
  'tls',
  'request',
  'wait',
  'download',
] as const;

export type PhaseName = (typeof PHASES)[number];

export interface Phase {
  name: PhaseName;
  label: string;
  /** Offset from request start, in milliseconds. */
  start: number;
  /** Duration in milliseconds. */
  duration: number;
}

export interface PhaseTimings {
  /** Stalled / queued before any network activity. */
  blocked: number;
  dns: number;
  /** TCP connect only (TLS subtracted, because HAR's `connect` includes it). */
  tcp: number;
  tls: number;
  /** Time spent uploading the request. */
  request: number;
  /** Time to first byte. */
  wait: number;
  download: number;
  total: number;
}

export interface TimingPhaseMeta {
  name: PhaseName;
  label: string;
  short: string;
  color: string;
  teach: string;
}

/**
 * One-line explanations shown when "Teach me" is enabled.
 * These are the teaching content of the product, not filler.
 */
export const PHASE_META: Record<PhaseName, TimingPhaseMeta> = {
  blocked: {
    name: 'blocked',
    label: 'Queued / blocked',
    short: 'queue',
    color: '#64748b',
    teach:
      'Blocked: the browser had to wait before sending (connection limit per host, a lock, or devtools throttling).',
  },
  dns: {
    name: 'dns',
    label: 'DNS lookup',
    short: 'dns',
    color: '#8b5cf6',
    teach:
      "DNS: the browser asks a resolver for the server's IP address, like looking up a phone number.",
  },
  tcp: {
    name: 'tcp',
    label: 'TCP connect',
    short: 'tcp',
    color: '#3b82f6',
    teach:
      'TCP connect: a three-way handshake opens a reliable connection to the server so bytes can flow both ways.',
  },
  tls: {
    name: 'tls',
    label: 'TLS handshake',
    short: 'tls',
    color: '#14b8a6',
    teach:
      'TLS handshake: the browser and server agree on encryption keys and verify the certificate proves the server identity.',
  },
  request: {
    name: 'request',
    label: 'Request sent',
    short: 'send',
    color: '#f59e0b',
    teach:
      'Request sent: the browser uploads the request line, headers and body to the server.',
  },
  wait: {
    name: 'wait',
    label: 'Waiting (TTFB)',
    short: 'ttfb',
    color: '#f97316',
    teach:
      'Waiting (TTFB): the server is thinking. Time to first byte includes database queries, rendering and any upstream calls.',
  },
  download: {
    name: 'download',
    label: 'Response download',
    short: 'down',
    color: '#22c55e',
    teach:
      'Response download: the response body travels back over the network. Bigger payloads and slow links make this phase longer.',
  },
};
