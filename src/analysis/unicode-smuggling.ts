/**
 * Invisible-Unicode analysis: finds characters that render as nothing, decodes text smuggled in them,
 * and recognises the legitimate uses (emoji flags and sequences, presentation selectors, ZWNJ/ZWJ in
 * Persian and Indic scripts, direction marks in right-to-left text).
 *
 * Smuggling schemes decoded:
 *  - Unicode tag characters (U+E0020–E007E mirror printable ASCII; "ASCII smuggling").
 *  - Variation selectors (VS1–16 = bytes 0–15, VS17–256 = bytes 16–255) appended to a visible character.
 *  - Zero-width binary: two distinct zero-width characters used as 0 and 1 bits.
 */

export type InvisibleKind = 'tag' | 'variation_selector' | 'zero_width' | 'bidi_override' | 'bidi_isolate' | 'bidi_mark' | 'soft_hyphen' | 'other_format';

export interface InvisibleRun {
  /** UTF-16 index of the first invisible code point. */
  start: number;
  /** UTF-16 index just past the last invisible code point. */
  end: number;
  codepoints: number[];
  kinds: InvisibleKind[];
  /** Code point immediately before the run, if any. */
  before?: number;
}

export type PayloadKind = 'tag_characters' | 'variation_selectors' | 'zero_width_binary';

export interface HiddenPayload {
  kind: PayloadKind;
  decoded: string;
  run: InvisibleRun;
  /** True when the decoded content is long and readable; false for short IDs (watermarks). */
  substantial: boolean;
}

const ZERO_WIDTH = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x180e]);
const BIDI_OVERRIDE = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e]);
const BIDI_ISOLATE = new Set([0x2066, 0x2067, 0x2068, 0x2069]);
const BIDI_MARK = new Set([0x200e, 0x200f, 0x061c]);
const CF_RE = /^\p{Cf}$/u;

export function classifyInvisible(cp: number): InvisibleKind | undefined {
  if (cp >= 0xe0000 && cp <= 0xe007f) return 'tag';
  if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) return 'variation_selector';
  if (ZERO_WIDTH.has(cp)) return 'zero_width';
  if (BIDI_OVERRIDE.has(cp)) return 'bidi_override';
  if (BIDI_ISOLATE.has(cp)) return 'bidi_isolate';
  if (BIDI_MARK.has(cp)) return 'bidi_mark';
  if (cp === 0x00ad) return 'soft_hyphen';
  if (CF_RE.test(String.fromCodePoint(cp))) return 'other_format';
  return undefined;
}

/** Quick check so callers can skip pure-visible text cheaply. */
export function hasInvisible(text: string): boolean {
  return /[\p{Cf}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/u.test(text);
}

export function findInvisibleRuns(text: string): InvisibleRun[] {
  if (!hasInvisible(text)) return [];
  const runs: InvisibleRun[] = [];
  let current: InvisibleRun | undefined;
  let prev: number | undefined;
  let i = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    const kind = classifyInvisible(cp);
    if (kind) {
      if (!current) current = { start: i, end: i, codepoints: [], kinds: [], ...(prev !== undefined ? { before: prev } : {}) };
      current.codepoints.push(cp);
      if (!current.kinds.includes(kind)) current.kinds.push(kind);
      current.end = i + ch.length;
    } else {
      if (current) runs.push(current);
      current = undefined;
      prev = cp;
    }
    i += ch.length;
  }
  if (current) runs.push(current);
  return runs;
}

/** Text a human can read: mostly letters/digits/punctuation/spaces, at least a few letters, no controls. */
export function isReadableText(s: string, minLetters = 3): boolean {
  if (s.length < 4) return false;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(s)) return false;
  const chars = [...s];
  const printable = chars.filter((c) => /[\p{L}\p{N}\p{P}\p{S}\p{Zs}\n\t]/u.test(c)).length;
  const letters = chars.filter((c) => /\p{L}/u.test(c)).length;
  return printable / chars.length >= 0.85 && letters >= minLetters;
}

const utf8 = new TextDecoder('utf-8', { fatal: true });
function decodeUtf8(bytes: number[]): string | undefined {
  try {
    return utf8.decode(Uint8Array.from(bytes));
  } catch {
    return undefined;
  }
}

const BLACK_FLAG = 0x1f3f4;
const CANCEL_TAG = 0xe007f;

/** Emoji subdivision flags (🏴 + lowercase tag letters/digits + CANCEL TAG), e.g. the England/Scotland/Wales flags. */
function isSubdivisionFlag(run: InvisibleRun): boolean {
  const cps = run.codepoints;
  if (run.before !== BLACK_FLAG || cps[cps.length - 1] !== CANCEL_TAG || cps.length > 8) return false;
  return cps.slice(0, -1).every((cp) => (cp >= 0xe0061 && cp <= 0xe007a) || (cp >= 0xe0030 && cp <= 0xe0039));
}

function decodeTags(cps: number[]): string {
  return cps
    .filter((cp) => cp >= 0xe0020 && cp <= 0xe007e)
    .map((cp) => String.fromCharCode(cp - 0xe0000))
    .join('');
}

function decodeVariationSelectors(cps: number[]): string | undefined {
  const bytes: number[] = [];
  for (const cp of cps) {
    if (cp >= 0xfe00 && cp <= 0xfe0f) bytes.push(cp - 0xfe00);
    else if (cp >= 0xe0100 && cp <= 0xe01ef) bytes.push(cp - 0xe0100 + 16);
  }
  return decodeUtf8(bytes);
}

function decodeZeroWidthBinary(cps: number[]): string | undefined {
  const symbols = [...new Set(cps.filter((cp) => ZERO_WIDTH.has(cp)))];
  if (symbols.length !== 2 || cps.length < 32 || cps.length % 8 !== 0) return undefined;
  let best: string | undefined;
  for (const zero of symbols) {
    const bytes: number[] = [];
    for (let i = 0; i < cps.length; i += 8) {
      let byte = 0;
      for (let b = 0; b < 8; b++) byte = (byte << 1) | (cps[i + b] === zero ? 0 : 1);
      bytes.push(byte);
    }
    const text = decodeUtf8(bytes);
    if (text && isReadableText(text) && (!best || letterCount(text) > letterCount(best))) best = text;
  }
  return best;
}

const letterCount = (s: string): number => (s.match(/\p{L}/gu) ?? []).length;

/**
 * Decodes text smuggled in invisible characters. Legitimate uses are skipped:
 * subdivision flags, single presentation selectors, single ZWJ/ZWNJ/ZWSP joiners.
 */
export function extractHiddenPayloads(text: string): HiddenPayload[] {
  const out: HiddenPayload[] = [];
  for (const run of findInvisibleRuns(text)) {
    const tagCps = run.codepoints.filter((cp) => cp >= 0xe0000 && cp <= 0xe007f);
    if (tagCps.length > 0 && !isSubdivisionFlag(run)) {
      const decoded = decodeTags(tagCps);
      if (decoded.trim().length >= 3) out.push({ kind: 'tag_characters', decoded, run, substantial: isReadableText(decoded) });
      continue;
    }
    const vsCps = run.codepoints.filter((cp) => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef));
    // A single selector after an emoji or CJK character is ordinary presentation.
    if (vsCps.length >= 4) {
      const decoded = decodeVariationSelectors(vsCps);
      if (decoded && isReadableText(decoded)) out.push({ kind: 'variation_selectors', decoded, run, substantial: decoded.length >= 12 });
      continue;
    }
    const zwCps = run.codepoints.filter((cp) => ZERO_WIDTH.has(cp));
    if (zwCps.length >= 32) {
      const decoded = decodeZeroWidthBinary(zwCps);
      if (decoded) out.push({ kind: 'zero_width_binary', decoded, run, substantial: decoded.length >= 12 });
    }
  }
  return out;
}

const RTL_SCRIPT_RE = /[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}\p{Script=Adlam}]/u;

export interface BidiOverride {
  index: number;
  codepoint: number;
  /** Logical (stored) text affected by the override, up to the next PDF or 80 chars. */
  segment: string;
}

/**
 * Left-to-right/right-to-left OVERRIDE characters (U+202D/U+202E) in text without any right-to-left script.
 * They make text display in a different order than it is stored ("Trojan Source", "exe" filename tricks).
 * Direction marks, embeddings and isolates are used legitimately by i18n frameworks and are not reported.
 */
export function findBidiOverrides(text: string): BidiOverride[] {
  if (!/[\u202D\u202E]/.test(text) || RTL_SCRIPT_RE.test(text)) return [];
  const out: BidiOverride[] = [];
  const re = /[\u202D\u202E]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const rest = text.slice(m.index + 1);
    const pdf = rest.search(/[\u202C\u2069]/);
    out.push({ index: m.index, codepoint: m[0].charCodeAt(0), segment: rest.slice(0, pdf === -1 ? 80 : Math.min(pdf, 80)) });
  }
  return out;
}

/** "U+E0049 U+E0067 …" — a printable description of invisible characters, never the characters themselves. */
export function describeCodepoints(cps: number[], max = 8): string {
  const shown = cps.slice(0, max).map((cp) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`);
  return cps.length > max ? `${shown.join(' ')} … (${cps.length} total)` : shown.join(' ');
}
