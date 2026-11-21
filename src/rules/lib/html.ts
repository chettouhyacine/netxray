/**
 * Minimal HTML tag scanner. This is not a parser and must never be used to
 * render anything; it only extracts attributes from script/link tags in a
 * captured response body.
 */
export interface ExternalTag {
  tag: 'script' | 'link';
  url: string;
  hasIntegrity: boolean;
  crossOrigin: boolean;
}

const TAG_PATTERN = /<(script|link)\b([^>]*)>/gi;
const ATTRIBUTE_PATTERN = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;

function parseAttributes(input: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  let match: RegExpExecArray | null;
  const pattern = new RegExp(ATTRIBUTE_PATTERN.source, 'g');
  while ((match = pattern.exec(input)) !== null) {
    const key = (match[1] ?? '').toLowerCase();
    if (!key) continue;
    attributes[key] = match[2] ?? match[3] ?? match[4] ?? '';
  }
  return attributes;
}

/** Extracts external script and stylesheet references from an HTML string. */
export function extractExternalTags(html: string, documentUrl: string): ExternalTag[] {
  if (!html) return [];
  let base: URL;
  try {
    base = new URL(documentUrl);
  } catch {
    return [];
  }
  const result: ExternalTag[] = [];
  let match: RegExpExecArray | null;
  const pattern = new RegExp(TAG_PATTERN.source, 'gi');
  while ((match = pattern.exec(html)) !== null) {
    const tag = (match[1] ?? '').toLowerCase() as 'script' | 'link';
    const attributes = parseAttributes(match[2] ?? '');
    const reference =
      tag === 'script' ? attributes.src : attributes.rel?.toLowerCase() === 'stylesheet' ? attributes.href : undefined;
    if (!reference) continue;
    let resolved: URL;
    try {
      resolved = new URL(reference, base);
    } catch {
      continue;
    }
    if (resolved.origin === base.origin) continue;
    result.push({
      tag,
      url: resolved.toString(),
      hasIntegrity: Boolean(attributes.integrity),
      crossOrigin: attributes.crossorigin !== undefined,
    });
  }
  return result;
}
