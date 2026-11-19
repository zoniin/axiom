import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      // The CLI and HTTP server are exercised end to end in test/audit-cli.test.ts and test/server.test.ts.
      exclude: ['src/cli.ts'],
      reporter: ['text-summary', 'text'],
      thresholds: { statements: 90, branches: 80, functions: 88, lines: 92 },
    },
  },
});
