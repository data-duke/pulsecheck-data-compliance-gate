import { mkdir, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

/**
 * Write a file by writing a sibling and renaming it over the target. A symlink a merge request committed at `path` is
 * replaced, never followed, so the report cannot overwrite a file outside the checkout.
 */
export async function writeFileReplacing(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, content, { encoding: 'utf8', flag: 'wx' });
  await rename(temp, path);
}
