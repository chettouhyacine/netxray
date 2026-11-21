import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './missing-sri';

const html = `<!doctype html>
<html><head>
  <script src="https://cdn.other.com/lib.js"></script>
  <script src="https://cdn.other.com/pinned.js" integrity="sha384-abc" crossorigin="anonymous"></script>
  <script src="/local.js"></script>
  <link rel="stylesheet" href="https://fonts.other.com/font.css">
</head></html>`;

describe('missing-sri', () => {
  it('flags external scripts and styles without integrity', () => {
    const hits = rule.evaluate(
      makeContext({ resourceType: 'document', mimeType: 'text/html', responseBodyText: html }),
    );
    expect(hits).toHaveLength(2);
    expect(hits.map((hit) => hit.key)).toContain('script:https://cdn.other.com/lib.js');
    expect(hits.map((hit) => hit.key)).toContain('link:https://fonts.other.com/font.css');
  });

  it('ignores pinned, same-origin and non-HTML responses', () => {
    expect(
      rule.evaluate(
        makeContext({
          resourceType: 'document',
          mimeType: 'text/html',
          responseBodyText: '<script src="https://cdn.other.com/pinned.js" integrity="sha384-abc"></script>',
        }),
      ),
    ).toEqual([]);
    expect(rule.evaluate(makeContext({ mimeType: 'application/json' }))).toEqual([]);
    expect(rule.evaluate(makeContext({ resourceType: 'script', mimeType: 'text/html' }))).toEqual([]);
  });
});
