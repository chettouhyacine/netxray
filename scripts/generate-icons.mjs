/**
 * Renders public/icons/icon.svg into the PNG sizes declared in the manifest.
 *
 * Chromium (already installed for Playwright) rasterizes the vector at each
 * exact size, which stays sharper than downscaling one large bitmap.
 *
 * Usage: node scripts/generate-icons.mjs
 */
import { mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright-core';

const SIZES = [16, 32, 48, 128];
const root = process.cwd();
const sourcePath = path.join(root, 'public', 'icons', 'icon.svg');
const outputDir = path.join(root, 'public', 'icons');

const svg = await readFile(sourcePath, 'utf8');
await mkdir(outputDir, { recursive: true });

const browser = await chromium.launch();
try {
  for (const size of SIZES) {
    const page = await browser.newPage({
      viewport: { width: size, height: size },
      deviceScaleFactor: 1,
    });
    await page.setContent(
      `<!doctype html><style>
        html, body { margin: 0; padding: 0; background: transparent; }
        svg { display: block; width: ${size}px; height: ${size}px; }
      </style>${svg}`,
    );
    await page.screenshot({
      path: path.join(outputDir, `icon${size}.png`),
      omitBackground: true,
    });
    await page.close();
    console.log(`wrote public/icons/icon${size}.png`);
  }
} finally {
  await browser.close();
}
