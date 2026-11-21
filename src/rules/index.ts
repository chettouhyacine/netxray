import type { Rule } from './types';

import broadScope from './cookies/broad-scope';
import missingHttpOnly from './cookies/missing-httponly';
import missingSameSite from './cookies/missing-samesite';
import missingSecure from './cookies/missing-secure';
import sessionJsReadable from './cookies/session-js-readable';

import cspMissing from './headers/csp-missing';
import cspWeak from './headers/csp-weak';
import frameOptionsMissing from './headers/frame-options-missing';
import hstsMissing from './headers/hsts-missing';
import hstsWeak from './headers/hsts-weak';
import permissionsPolicyMissing from './headers/permissions-policy-missing';
import referrerPolicyMissing from './headers/referrer-policy-missing';
import xctoMissing from './headers/xcto-missing';

import corsPermissive from './cors/permissive';
import corsReflectedOrigin from './cors/reflected-origin';
import corsWildcardCredentials from './cors/wildcard-credentials';

import insecureHttp from './transport/insecure-http';
import mixedContent from './transport/mixed-content';

import certificateExpiring from './tls/certificate-expiring';
import hostnameMismatch from './tls/hostname-mismatch';
import outdatedProtocol from './tls/outdated-protocol';
import weakCipher from './tls/weak-cipher';

import secretInResponse from './leaks/secret-in-response';
import secretInUrl from './leaks/secret-in-url';
import serverVersionDisclosure from './leaks/server-version';
import verboseError from './leaks/verbose-error';

import algNone from './jwt/alg-none';
import jwtLongExpiry from './jwt/long-expiry';
import jwtMissingExp from './jwt/missing-exp';
import jwtSensitivePayload from './jwt/sensitive-payload';

import missingSri from './third-party/missing-sri';
import tracker from './third-party/tracker';
import unknownOrigin from './third-party/unknown-origin';

import cacheSensitiveResponse from './caching/sensitive-cacheable';

/**
 * The rule registry. Order is irrelevant for correctness; the UI sorts by
 * severity. Add new rules here after creating the module and its test.
 */
export const rules: Rule[] = [
  // cookies
  sessionJsReadable,
  missingHttpOnly,
  missingSecure,
  missingSameSite,
  broadScope,
  // headers
  cspMissing,
  cspWeak,
  hstsMissing,
  hstsWeak,
  xctoMissing,
  frameOptionsMissing,
  referrerPolicyMissing,
  permissionsPolicyMissing,
  // cors
  corsWildcardCredentials,
  corsReflectedOrigin,
  corsPermissive,
  // transport + tls
  mixedContent,
  insecureHttp,
  outdatedProtocol,
  weakCipher,
  certificateExpiring,
  hostnameMismatch,
  // leaks
  secretInUrl,
  secretInResponse,
  verboseError,
  serverVersionDisclosure,
  // jwt
  algNone,
  jwtMissingExp,
  jwtLongExpiry,
  jwtSensitivePayload,
  // third party
  tracker,
  unknownOrigin,
  missingSri,
  // caching
  cacheSensitiveResponse,
];

export const rulesById = new Map(rules.map((rule) => [rule.id, rule]));

export type { Rule } from './types';
