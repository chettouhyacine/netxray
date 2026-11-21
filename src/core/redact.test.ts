import { describe, expect, it } from 'vitest';
import {
  findSecretsInText,
  isSensitiveName,
  maskSecret,
  redactHeaderValue,
  redactHeaders,
  redactUrl,
} from './redact';

describe('maskSecret', () => {
  it('keeps a recognisable prefix and suffix', () => {
    expect(maskSecret('abcdefghijklmnopqrstuvwxyz')).toBe('abcd' + '•'.repeat(18) + 'wxyz');
  });

  it('fully masks short values', () => {
    expect(maskSecret('short')).toBe('•••••');
    expect(maskSecret('')).toBe('');
  });
});

describe('redactUrl', () => {
  it('masks sensitive query values and userinfo', () => {
    const result = redactUrl('https://user:pass@example.com/reset?token=supersecrettoken&q=hello');
    expect(result).not.toContain('supersecrettoken');
    expect(result).not.toContain('pass@');
    expect(result).toContain('q=hello');
    expect(result).toContain('token=');
  });

  it('returns malformed URLs unchanged', () => {
    expect(redactUrl('not a url')).toBe('not a url');
  });
});

describe('header redaction', () => {
  it('masks authorization and cookie values', () => {
    expect(redactHeaderValue('Authorization', 'Bearer api-secret-value-123456')).not.toContain('secret-value');
    expect(redactHeaderValue('Cookie', 'sid=abcdefghijklmnop; theme=dark')).toContain('theme=dark');
    expect(redactHeaderValue('Set-Cookie', 'sid=abcdefghijklmnop; HttpOnly')).toContain('HttpOnly');
    expect(redactHeaderValue('X-Api-Key', 'abcdefghijklmnop')).toContain('•');
    expect(redactHeaderValue('Content-Type', 'text/html')).toBe('text/html');
  });

  it('redacts a header map', () => {
    const redacted = redactHeaders({ authorization: 'Bearer 1234567890abcdef', 'content-type': 'text/html' });
    expect(redacted.authorization).not.toContain('1234567890abcdef');
    expect(redacted['content-type']).toBe('text/html');
  });
});

describe('secret scanning', () => {
  it('detects common credential shapes', () => {
    const body = [
      '{"aws":"AKIAIOSFODNN7EXAMPLE"}',
      '{"key":"sk_live_abcdefghijklmnop123456"}',
      '{"url":"postgres://user:pass@db.example.com/app"}',
      '-----BEGIN RSA PRIVATE KEY-----',
    ].join('\n');
    const kinds = findSecretsInText(body).map((match) => match.kind);
    expect(kinds).toContain('aws-access-key');
    expect(kinds).toContain('stripe-key');
    expect(kinds).toContain('database-url');
    expect(kinds).toContain('private-key');
  });

  it('deduplicates repeated secrets and handles empty text', () => {
    const text = 'AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE';
    expect(findSecretsInText(text)).toHaveLength(1);
    expect(findSecretsInText('')).toEqual([]);
  });

  it('recognises sensitive parameter names', () => {
    expect(isSensitiveName('access_token')).toBe(true);
    expect(isSensitiveName('apiKey')).toBe(true);
    expect(isSensitiveName('search')).toBe(false);
  });
});
