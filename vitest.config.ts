import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // The demo script and the barrel are not part of the library surface.
      exclude: ['src/index.ts', 'src/example.ts'],
      reporter: ['text', 'lcov', 'json-summary'],
      reportsDirectory: 'coverage',
      thresholds: {
        lines: 95,
        statements: 95,
        functions: 95,
        branches: 90,
      },
    },
  },
});
