import type { Remediation } from '../../core/types';

/** Builds the standard three-framework remediation list. */
export function remediation(
  express: string,
  nextjs: string,
  nginx: string,
  notes?: { express?: string; nextjs?: string; nginx?: string },
): Remediation[] {
  return [
    { framework: 'express', language: 'js', code: express.trim(), note: notes?.express },
    { framework: 'nextjs', language: 'ts', code: nextjs.trim(), note: notes?.nextjs },
    { framework: 'nginx', language: 'nginx', code: nginx.trim(), note: notes?.nginx },
  ];
}

/** Remediation for a response header that should be present. */
export function headerRemediation(options: {
  header: string;
  value: string;
  nextHeader?: string;
  expressCode?: string;
  nextjsCode?: string;
  nginxCode?: string;
}): Remediation[] {
  const express =
    options.expressCode ??
    `// Express: set the header on every response\napp.use((req, res, next) => {\n  res.setHeader('${options.header}', "${options.value}");\n  next();\n});`;
  const nextjs =
    options.nextjsCode ??
    `// next.config.mjs\nconst nextConfig = {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [{ key: '${options.nextHeader ?? options.header}', value: "${options.value}" }],\n      },\n    ];\n  },\n};\nexport default nextConfig;`;
  const nginx =
    options.nginxCode ??
    `# nginx\nserver {\n  add_header ${options.header} "${options.value}" always;\n}`;
  return remediation(express, nextjs, nginx);
}
