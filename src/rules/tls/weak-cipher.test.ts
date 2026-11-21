import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './weak-cipher';

describe('tls-weak-cipher', () => {
  it('flags RC4 and 3DES suites', () => {
    expect(rule.evaluate(makeContext({ tls: { cipher: 'TLS_RSA_WITH_RC4_128_SHA' } }))).toHaveLength(1);
    expect(rule.evaluate(makeContext({ tls: { cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' } }))).toHaveLength(1);
  });

  it('accepts modern AEAD suites and missing data', () => {
    expect(rule.evaluate(makeContext({ tls: { cipher: 'TLS_AES_256_GCM_SHA384' } }))).toEqual([]);
    expect(rule.evaluate(makeContext())).toEqual([]);
  });
});
