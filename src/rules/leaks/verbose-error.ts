import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const STACK_MARKERS = [
  /at\s+[A-Za-z0-9_.$]+\s+\([^)]*:\d+:\d+\)/,
  /\bnode_modules[\\/]/,
  /Traceback \(most recent call last\)/,
  /\bSQLSTATE\b/i,
  /\b(?:ER_|ORA-|PG::)[A-Z0-9]+/,
  /Microsoft\.Data\.SqlClient/,
  /\bat\s+javax?\./,
  /\/var\/www\//,
  /\/home\/[a-z0-9_-]+\//i,
  /\bstack\s*["']?\s*:\s*["']/i,
];

const rule: Rule = {
  id: 'verbose-error',
  severity: 'medium',
  title: 'Error response exposes internals',
  what: 'A failing response returns a stack trace, database error or file paths instead of a generic error message.',
  why: 'Stack traces tell an attacker your framework versions, file layout, ORM, query fragments and sometimes credentials. Every detail narrows the search for an exploitable bug.',
  attack:
    'The attacker sends malformed input until a 500 error reveals a Prisma/SQL error with table and column names, then crafts targeted SQL injection or mass-assignment attacks.',
  tags: ['leaks', 'errors'],
  appliesTo: 'response',
  remediation: remediation(
    `// Express: central error handler, generic message in production
app.use((err, req, res, _next) => {
  console.error(err); // server logs only
  res.status(500).json({
    error: 'Internal server error',
    requestId: req.id, // safe correlation id
  });
});`,
    `// Next.js Route Handler
export async function GET() {
  try {
    return Response.json(await loadData());
  } catch (error) {
    console.error(error);
    return Response.json({ error: 'Internal server error' }, { status: 500 });
  }
}`,
    `# nginx: replace upstream error pages
proxy_intercept_errors on;
error_page 500 502 503 504 /50x.html;`,
  ),
  evaluate(ctx) {
    if (ctx.event.status < 400) return [];
    const body = ctx.event.responseBodyText;
    if (!body) return [];
    const marker = STACK_MARKERS.find((pattern) => pattern.test(body));
    if (!marker) return [];
    return [
      {
        key: `status:${ctx.event.status}`,
        message: `Status ${ctx.event.status} returned a stack trace or internal error detail.`,
        detail: 'Details like file paths, package names and SQL fragments help attackers map the backend.',
        evidence: body.slice(0, 200),
      },
    ];
  },
};

export default rule;
