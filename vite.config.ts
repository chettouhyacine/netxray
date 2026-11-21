import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Multi-page build:
 *  - devtools.html  -> the tiny DevTools bootstrap that registers the panel
 *  - panel.html     -> the React application shown inside the DevTools panel
 * The service worker is bundled separately by scripts/build-background.mjs.
 */
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'chrome116',
    sourcemap: false,
    rollupOptions: {
      input: {
        devtools: 'devtools.html',
        panel: 'panel.html',
      },
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
  worker: {
    format: 'es',
  },
});
