// Runs after `ncc build src/cliMain.ts -o cli/dist`: makes cli/dist/index.js a real executable.
// npm links a package's `bin` file directly on Unix, so it needs a shebang and the executable bit; ncc writes neither.
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const entry = join(dirname(fileURLToPath(import.meta.url)), 'dist', 'index.js');
if (!existsSync(entry)) {
  console.error(`postbuild: ${entry} does not exist; run the ncc build first.`);
  process.exit(1);
}
const SHEBANG = '#!/usr/bin/env node\n';
const source = readFileSync(entry, 'utf8');
if (!source.startsWith('#!')) writeFileSync(entry, SHEBANG + source);
chmodSync(entry, 0o755);
console.log(`postbuild: ${entry} is executable.`);
