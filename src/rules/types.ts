import type { DecodedJwt } from '../core/jwt';
import { ruleMeta } from './catalog';
import type {
  CookieObservation,
  Finding,
  NetworkEvent,
  PageContext,
  Remediation,
  Severity,
} from '../core/types';

/** Everything a rule may look at. Rules never perform I/O. */
export interface RuleContext {
  event: NetworkEvent;
  page: PageContext;
  /** Cookies chrome.cookies reports for the page (may be empty without permission). */
  cookies: CookieObservation[];
  /** JWTs decoded from this event: URL, headers, cookies and body. */
  jwts: DecodedJwt[];
}

export interface RuleHit {
  /** Stable identity of the affected thing (cookie name, header, host…). */
  key: string;
  /** Specific one-liner, e.g. "Cookie `sid` is not HttpOnly". */
  message: string;
  detail?: string;
  /** Masked value shown in the finding drawer. */
  evidence?: string;
}

export type RuleAppliesTo = 'request' | 'response' | 'document';

/**
 * A security rule. Adding a rule means adding one file that default-exports a
 * Rule, then registering it in `src/rules/index.ts`.
 */
export interface Rule {
  id: string;
  severity: Severity;
  title: string;
  /** Plain-language: what is this? */
  what: string;
  /** Plain-language: why does it matter? */
  why: string;
  /** How an attacker could use it. */
  attack: string;
  /** How to fix it, with snippets where relevant. */
  remediation: Remediation[];
  tags: string[];
  appliesTo: RuleAppliesTo;
  evaluate(ctx: RuleContext): RuleHit[];
}

/** Converts a rule hit into the UI/export finding model. */
export function toFinding(rule: Rule, hit: RuleHit, ctx: RuleContext): Finding {
  const meta = ruleMeta(rule.id);
  let domain = '';
  try {
    domain = new URL(ctx.event.url).hostname;
  } catch {
    domain = '';
  }
  return {
    id: `${rule.id}:${hit.key}`,
    ruleId: rule.id,
    severity: rule.severity,
    title: rule.title,
    what: rule.what,
    why: rule.why,
    attack: rule.attack,
    remediation: rule.remediation,
    message: hit.message,
    detail: hit.detail,
    evidence: hit.evidence,
    eventId: ctx.event.id,
    url: ctx.event.url,
    domain,
    tags: rule.tags,
    attackClass: meta.attack,
    confidence: meta.confidence,
  };
}
