/** Small URL helpers that never throw on malformed captures. */

export function safeUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

export function hostOf(raw: string): string {
  return safeUrl(raw)?.hostname.toLowerCase() ?? '';
}

export function originOf(raw: string): string {
  const url = safeUrl(raw);
  return url ? url.origin : '';
}

export function isHttpsUrl(raw: string): boolean {
  return safeUrl(raw)?.protocol === 'https:';
}

export function isHttpUrl(raw: string): boolean {
  return safeUrl(raw)?.protocol === 'http:';
}

export function pathOf(raw: string): string {
  const url = safeUrl(raw);
  return url ? `${url.pathname}${url.search}` : raw;
}

export function queryOf(raw: string): Record<string, string[]> {
  const url = safeUrl(raw);
  const result: Record<string, string[]> = {};
  if (!url) return result;
  for (const [key, value] of url.searchParams.entries()) {
    (result[key] ??= []).push(value);
  }
  return result;
}

/** Common multi-label public suffixes; enough to avoid false "same site" matches. */
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'co.jp',
  'ne.jp',
  'com.au',
  'net.au',
  'org.au',
  'co.nz',
  'co.in',
  'com.br',
  'com.mx',
  'co.za',
  'com.cn',
  'com.tr',
]);

/** Best-effort registrable domain ("docs.example.co.uk" -> "example.co.uk"). */
export function registrableDomain(host: string): string {
  const normalized = host.toLowerCase().replace(/\.$/, '');
  const parts = normalized.split('.').filter(Boolean);
  if (parts.length <= 2) return normalized;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

/** A request is third-party when its registrable domain differs from the page's. */
export function isThirdParty(raw: string, pageOrigin: string): boolean {
  const target = registrableDomain(hostOf(raw));
  const pageHost = hostOf(pageOrigin);
  if (!target || !pageHost) return false;
  return target !== registrableDomain(pageHost);
}

/** True for hosts that are definitionally local/dev traffic. */
export function isLocalHost(host: string): boolean {
  return (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host.endsWith('.localhost') ||
    host.endsWith('.test') ||
    host.endsWith('.local')
  );
}
