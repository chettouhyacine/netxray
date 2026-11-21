/**
 * The four attack classes NetXRay v1 reports by default.
 *
 * The capture layer sees traffic, not application source, so v1 only claims
 * attacks that leave a strong, unambiguous signal on the wire. Everything else
 * (CSP, HSTS, TLS, trackers, cache policy, …) still exists as an "extended"
 * check, but is hidden by default to keep the signal trustworthy.
 */
export const ATTACK_IDS = [
  'session-hijacking',
  'cors-data-theft',
  'clickjacking',
  'credential-leakage',
] as const;

export type AttackClass = (typeof ATTACK_IDS)[number];

/** How sure the rule is that the observed evidence is a real problem. */
export type Confidence = 'high' | 'medium' | 'low';

/** `v1` = the four high-confidence attack classes; `all` = every rule. */
export type AnalysisFocus = 'v1' | 'all';

export interface AttackDefinition {
  id: AttackClass;
  label: string;
  short: string;
  description: string;
}

export const ATTACKS: readonly AttackDefinition[] = [
  {
    id: 'session-hijacking',
    label: 'Session hijacking',
    short: 'Steal a logged-in session',
    description:
      'A session cookie is readable by page scripts or can travel over plain HTTP, so one injected script or one network hop is enough to take over the account.',
  },
  {
    id: 'cors-data-theft',
    label: 'Cross-origin data theft',
    short: 'Read private data from another site',
    description:
      'CORS trusts an origin it should not, so a page the user visits can read authenticated API responses with the user’s cookies.',
  },
  {
    id: 'clickjacking',
    label: 'Clickjacking',
    short: 'Click a hidden page',
    description:
      'The document can be framed by any site, so an attacker can hide your real UI under a fake button and turn a click into a destructive action.',
  },
  {
    id: 'credential-leakage',
    label: 'Credential leakage',
    short: 'Secrets exposed in traffic',
    description:
      'Passwords, API keys or unsigned tokens appear in URLs or response bodies, where logs, screenshots, caches and other scripts can pick them up.',
  },
];

export const ATTACK_BY_ID: Record<AttackClass, AttackDefinition> = Object.fromEntries(
  ATTACKS.map((attack) => [attack.id, attack]),
) as Record<AttackClass, AttackDefinition>;

export function isAttackClass(value: string | null | undefined): value is AttackClass {
  return typeof value === 'string' && (ATTACK_IDS as readonly string[]).includes(value);
}
