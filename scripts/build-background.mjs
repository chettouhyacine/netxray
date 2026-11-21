import { build } from 'esbuild';

/**
 * MV3 service workers must be plain (bundled) JS. Vite handles the HTML pages,
 * esbuild produces dist/background.js as an ES module service worker.
 */
await build({
  entryPoints: ['src/background/index.ts'],
  bundle: true,
  format: 'esm',
  target: 'chrome116',
  outfile: 'dist/background.js',
  sourcemap: false,
  legalComments: 'none',
  logLevel: 'info',
});
