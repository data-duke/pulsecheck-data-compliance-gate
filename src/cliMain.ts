/**
 * Entry point of the `pulsecheck-gate` binary: supplies the real network-adjacent dependencies (git, files, the process)
 * to `runCli` (cli.ts). Kept apart so cli.ts can be imported by tests without running anything.
 */
import { runCli } from './cli.js';
import { readGitDiff } from './gitDiff.js';
import { writeFileReplacing } from './safeWrite.js';

runCli(process.argv.slice(2), process.env, {
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
  cwd: process.cwd(),
  writeFile: writeFileReplacing,
  readDiff: readGitDiff,
})
  .then((code) => {
    process.exitCode = code;
  })
  .catch((e: unknown) => {
    // runCli does not throw; this is the last line of defence, and it exits 2 (an error in the tool, not a verdict).
    process.stderr.write(`error: pulsecheck-gate crashed: ${(e as Error)?.message ?? e}\n`);
    process.exitCode = 2;
  });
