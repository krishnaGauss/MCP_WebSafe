import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  platform: 'node',
  target: 'node22',
  sourcemap: true,
  clean: true,
  banner: { js: '#!/usr/bin/env node' },
  external: ['node:sqlite'],
  // node:sqlite only exists with the prefix; keep it.
  removeNodeProtocol: false,
});
