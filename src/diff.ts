/**
 * Minimal unified-diff parser.
 *
 * We only need enough fidelity to: (a) attribute each line to a file + line
 * number + side, and (b) recover same-hunk minus/plus pairs so the scanner can
 * detect "secret was hashed in the same change" patterns. We deliberately do
 * NOT try to be a full git-diff parser (renames, mode changes, binary blobs)
 * — those carry no scannable text content.
 */

export type LineSide = 'added' | 'removed' | 'context';

export interface DiffLine {
  side: LineSide;
  file: string;
  /** 1-based line number in the relevant file version, or null for unknowable. */
  lineNo: number | null;
  text: string;
  /** Index of the hunk this line belongs to (within its file). */
  hunkIndex: number;
}

export interface DiffHunk {
  file: string;
  hunkIndex: number;
  lines: DiffLine[];
}

export interface ParsedDiff {
  hunks: DiffHunk[];
  lines: DiffLine[];
}

const FILE_HEADER_RE = /^diff --git a\/(.+?) b\/(.+)$/;
const NEW_FILE_RE = /^\+\+\+ b\/(.+)$/;
const OLD_FILE_RE = /^--- a\/(.+)$/;
const HUNK_HEADER_RE = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/**
 * Parse a unified diff string into hunks and a flat line list.
 *
 * `lineNo` is the new-file line number for added/context lines and the
 * old-file line number for removed lines.
 */
export function parseDiff(diff: string): ParsedDiff {
  const hunks: DiffHunk[] = [];
  const lines: DiffLine[] = [];

  let currentFile = '';
  let hunkCounterForFile = 0;
  let currentHunk: DiffHunk | null = null;
  let oldLineNo = 0;
  let newLineNo = 0;

  const rawLines = diff.split('\n');

  for (const raw of rawLines) {
    const gitHeader = FILE_HEADER_RE.exec(raw);
    if (gitHeader) {
      // Prefer the "b/" path (post-change name); fall back to "a/".
      currentFile = gitHeader[2] || gitHeader[1];
      hunkCounterForFile = 0;
      currentHunk = null;
      continue;
    }

    const newFile = NEW_FILE_RE.exec(raw);
    if (newFile) {
      if (newFile[1] !== '/dev/null') currentFile = newFile[1];
      continue;
    }

    const oldFile = OLD_FILE_RE.exec(raw);
    if (oldFile) {
      // Only adopt the old path when we don't yet have a file (e.g. deletions
      // where +++ is /dev/null). Otherwise keep the new-file name.
      if (!currentFile && oldFile[1] !== '/dev/null') currentFile = oldFile[1];
      continue;
    }

    const hunkHeader = HUNK_HEADER_RE.exec(raw);
    if (hunkHeader) {
      oldLineNo = Number(hunkHeader[1]);
      newLineNo = Number(hunkHeader[3]);
      currentHunk = {
        file: currentFile,
        hunkIndex: hunkCounterForFile,
        lines: [],
      };
      hunks.push(currentHunk);
      hunkCounterForFile += 1;
      continue;
    }

    // Skip diff metadata lines that aren't content.
    if (
      raw.startsWith('index ') ||
      raw.startsWith('new file mode') ||
      raw.startsWith('deleted file mode') ||
      raw.startsWith('old mode') ||
      raw.startsWith('new mode') ||
      raw.startsWith('similarity index') ||
      raw.startsWith('rename from') ||
      raw.startsWith('rename to') ||
      raw.startsWith('Binary files') ||
      raw.startsWith('\\ No newline')
    ) {
      continue;
    }

    if (!currentHunk) continue; // content outside a hunk — ignore.

    let side: LineSide;
    let lineNo: number | null;
    let text: string;

    if (raw.startsWith('+')) {
      side = 'added';
      text = raw.slice(1);
      lineNo = newLineNo;
      newLineNo += 1;
    } else if (raw.startsWith('-')) {
      side = 'removed';
      text = raw.slice(1);
      lineNo = oldLineNo;
      oldLineNo += 1;
    } else if (raw.startsWith(' ')) {
      side = 'context';
      text = raw.slice(1);
      lineNo = newLineNo;
      oldLineNo += 1;
      newLineNo += 1;
    } else {
      // Empty line inside a hunk is treated as a context blank line.
      side = 'context';
      text = raw;
      lineNo = newLineNo;
      oldLineNo += 1;
      newLineNo += 1;
    }

    const lineObj: DiffLine = {
      side,
      file: currentFile,
      lineNo,
      text,
      hunkIndex: currentHunk.hunkIndex,
    };
    currentHunk.lines.push(lineObj);
    lines.push(lineObj);
  }

  return { hunks, lines };
}

/** All added (`+`) lines across the diff. */
export function addedLines(parsed: ParsedDiff): DiffLine[] {
  return parsed.lines.filter((l) => l.side === 'added');
}

/** All removed (`-`) lines across the diff. */
export function removedLines(parsed: ParsedDiff): DiffLine[] {
  return parsed.lines.filter((l) => l.side === 'removed');
}

export interface MinusPlusPair {
  minus: DiffLine;
  plus: DiffLine;
  /** True when both lines belong to the same hunk of the same file. */
  sameHunk: boolean;
}

/**
 * Enumerate minus/plus line pairs.
 *
 * `window` controls scope:
 *  - 'same_hunk': only pair removed+added lines within the same hunk.
 *  - 'same_file': pair any removed line in a file with any added line in the
 *    same file (used to detect cross-hunk patterns, which the scanner then
 *    downgrades).
 *
 * Each returned pair records `sameHunk` so the caller can grade block vs review.
 */
/**
 * Hard ceiling on enumerated before/after pairs, whatever the bucketing.
 *
 * Bucketing removes the cross-file blow-up but not the within-bucket one: a
 * single hunk that rewrites 10k lines is still 10k x 10k. The caller marks the
 * scan incomplete when this trips, so a truncated pair set floors the verdict
 * rather than reading as a clean pass.
 */
export const MAX_MINUS_PLUS_PAIRS = 200_000;

export function minusPlusPairs(
  parsed: ParsedDiff,
  window: 'same_hunk' | 'same_file',
): { pairs: MinusPlusPair[]; truncated: boolean } {
  const pairs: MinusPlusPair[] = [];
  const minus = removedLines(parsed);
  const plus = addedLines(parsed);

  // BUCKET FIRST, then pair within a bucket.
  //
  // This used to be a flat nested loop over every removed x every added line in
  // the WHOLE diff, with the `m.file !== p.file` test inside it — so the cost was
  // quadratic in total diff size even though almost every pair it built was
  // immediately discarded. An independent security review measured the real
  // shipped `dc-safeguard-removed` rule at 147 ms for 500+500 lines, 1323 ms for
  // 2000+2000 and 8169 ms for 4000+4000 (a clean x4 per doubling), extrapolating
  // to minutes at the 5 MB diff cap — reachable by an ordinary large refactor PR,
  // and reported as `pass` with no warning because this evaluator had no budget
  // check either (added by the caller, below).
  //
  // Pairing inside a bucket is the same set of pairs, just without building the
  // ones that fail the filter: cost becomes the sum of m_f x p_f per bucket
  // rather than (sum m) x (sum p). For `same_hunk` the bucket is the hunk, which
  // is tighter still. A 4000+4000 diff spread over 100 files goes from 16M
  // candidate pairs to ~160k.
  const key = (l: { file: string; hunkIndex: number }) =>
    window === 'same_hunk' ? `${l.file}\u0000${l.hunkIndex}` : l.file;

  const plusByKey = new Map<string, typeof plus>();
  for (const p of plus) {
    const k = key(p);
    const bucket = plusByKey.get(k);
    if (bucket) bucket.push(p);
    else plusByKey.set(k, [p]);
  }

  for (const m of minus) {
    const bucket = plusByKey.get(key(m));
    if (!bucket) continue;
    for (const p of bucket) {
      // Still recomputed rather than assumed: for `same_file` the bucket key is
      // the file alone, so two lines in one bucket may be in different hunks.
      pairs.push({ minus: m, plus: p, sameHunk: m.hunkIndex === p.hunkIndex });
      // Report truncation, never infer it. A caller comparing `length >= CAP`
      // cannot tell a diff that produced EXACTLY the cap's worth of complete
      // pairs from one that was cut short, and would floor the verdict on a
      // scan that actually finished.
      if (pairs.length >= MAX_MINUS_PLUS_PAIRS) return { pairs, truncated: true };
    }
  }
  return { pairs, truncated: false };
}
