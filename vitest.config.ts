import { defineConfig } from 'vitest/config';

// Self-contained config so this package's tests don't inherit the repo-root
// vitest setup (jsdom + React testing setup). This is a plain Node package.
export default defineConfig({
  root: __dirname,
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    setupFiles: [],
  },
});
