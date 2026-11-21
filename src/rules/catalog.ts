import type { AttackClass, Confidence } from '../core/attacks';

/**
 * Presentation metadata for every rule.
 *
 * Rules stay pure detectors; this catalog decides which attack class (if any)
 * a rule belongs to and how much confidence to place in its evidence. v1 only
 * surfaces findings that are both mapped to an attack class and `high`
 * confidence. Everything else remains available in extended mode.
 */
export interface RuleMeta {
  attack?: AttackClass;
  confidence: Confidence;
}

export const RULE_CATALOG: Record<string, RuleMeta> = {
  // Session hijacking: high confidence only when the evidence is direct.
  'cookie-session-js-readable': { attack: 'session-hijacking', confidence: 'high' },
  'cookie-missing-secure': { attack: 'session-hijacking', confidence: 'high' },
  'cookie-missing-httponly': { confidence: 'medium' },
  'cookie-missing-samesite': { confidence: 'medium' },
  'cookie-broad-scope': { confidence: 'low' },

  // Cross-origin data theft.
  'cors-reflected-origin': { attack: 'cors-data-theft', confidence: 'high' },
  'cors-wildcard-credentials': { attack: 'cors-data-theft', confidence: 'high' },
  'cors-permissive': { confidence: 'medium' },

  // Clickjacking.
  'header-frame-options-missing': { attack: 'clickjacking', confidence: 'high' },

  // Credential leakage.
  'secret-in-url': { attack: 'credential-leakage', confidence: 'high' },
  'secret-in-response': { attack: 'credential-leakage', confidence: 'high' },
  'jwt-alg-none': { attack: 'credential-leakage', confidence: 'high' },
  'jwt-sensitive-payload': { attack: 'credential-leakage', confidence: 'high' },

  // Extended checks: useful, but not one of the four v1 attack claims.
  'header-csp-missing': { confidence: 'high' },
  'header-csp-weak': { confidence: 'medium' },
  'header-hsts-missing': { confidence: 'high' },
  'header-hsts-weak': { confidence: 'low' },
  'header-xcto-missing': { confidence: 'low' },
  'header-referrer-policy-missing': { confidence: 'low' },
  'header-permissions-policy-missing': { confidence: 'low' },
  'mixed-content': { confidence: 'high' },
  'insecure-http': { confidence: 'high' },
  'tls-outdated-protocol': { confidence: 'high' },
  'tls-weak-cipher': { confidence: 'high' },
  'tls-certificate-expiring': { confidence: 'medium' },
  'tls-hostname-mismatch': { confidence: 'high' },
  'verbose-error': { confidence: 'medium' },
  'server-version-disclosure': { confidence: 'low' },
  'jwt-missing-exp': { confidence: 'medium' },
  'jwt-long-expiry': { confidence: 'low' },
  'third-party-tracker': { confidence: 'low' },
  'third-party-unknown': { confidence: 'low' },
  'missing-sri': { confidence: 'medium' },
  'cache-sensitive-response': { confidence: 'medium' },
};

const FALLBACK: RuleMeta = { confidence: 'medium' };

export function ruleMeta(ruleId: string): RuleMeta {
  return RULE_CATALOG[ruleId] ?? FALLBACK;
}
