import { defineConfig } from 'vitest/config';

// Self-contained config so this package's tests don't inherit the repo-root
// vitest setup (jsdom + React testing setup). This is a plain Node package.
//
// `css.postcss: {}` is an inline (empty) PostCSS config. Without it vite walks UP the
// directory tree, finds the repo-root postcss.config.js and tries to load `tailwindcss`,
// which this package does not install, so the run dies in CI ("Failed to load PostCSS
// config") while passing on a machine whose root node_modules happens to have it.
export default defineConfig({
  root: __dirname,
  css: { postcss: {} },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    setupFiles: [],
  },
});
