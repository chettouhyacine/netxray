import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/rules/**/*.ts', 'src/core/**/*.ts'],
      exclude: ['src/rules/**/*.test.ts', 'src/core/**/*.test.ts', 'src/rules/types.ts'],
      thresholds: {
        lines: 85,
        functions: 85,
        statements: 85,
      },
    },
  },
});
