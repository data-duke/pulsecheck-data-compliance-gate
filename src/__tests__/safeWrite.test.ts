import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, symlinkSync, writeFileSync, lstatSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFileReplacing } from '../safeWrite.js';

describe('writeFileReplacing', () => {
  it('replaces a symlink at the target instead of writing through it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'safe-write-'));
    const outside = join(dir, 'outside.txt');
    writeFileSync(outside, 'precious');
    const checkout = join(dir, 'checkout');
    await writeFileReplacing(join(checkout, 'seed'), 'x');
    symlinkSync(outside, join(checkout, 'report.json'));

    await writeFileReplacing(join(checkout, 'report.json'), '[]\n');

    expect(readFileSync(outside, 'utf8')).toBe('precious');
    expect(lstatSync(join(checkout, 'report.json')).isSymbolicLink()).toBe(false);
    expect(readFileSync(join(checkout, 'report.json'), 'utf8')).toBe('[]\n');
    expect(readdirSync(checkout).filter((f) => f.endsWith('.tmp'))).toEqual([]);
  });

  it('creates missing directories', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'safe-write-'));
    await writeFileReplacing(join(dir, 'a', 'b', 'r.json'), 'ok');
    expect(readFileSync(join(dir, 'a', 'b', 'r.json'), 'utf8')).toBe('ok');
  });
});
