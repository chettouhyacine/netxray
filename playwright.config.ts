import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  use: {
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node demo/server.mjs',
    url: 'http://localhost:4000/vulnerable/',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
