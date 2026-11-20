import { classifyInvisible, hasInvisible } from './unicode-smuggling.js';

/**
 * Folds obfuscated text into a plain form FOR PATTERN MATCHING ONLY. Reports always show the original text.
 *
 * Order matters:
 *   1. bidi_reversal   text stored after RIGHT-TO-LEFT OVERRIDE is reversed (it displays reversed)
 *   2. invisible_chars zero-width, tag, selector, bidi and other format characters are removed
 *   3. nfkc            fullwidth, mathematical alphanumerics, ligatures, circled letters → ASCII
 *   4. spaced_letters  "i g n o r e" / "i.g.n.o.r.e" → "ignore"
 *   5. homoglyph       Cyrillic/Greek/Armenian look-alikes inside Latin words → Latin
 *   6. leetspeak       digits/symbols inside words that also contain letters → letters
 */
export type Transform = 'bidi_reversal' | 'invisible_chars' | 'nfkc' | 'spaced_letters' | 'homoglyph' | 'leetspeak';

export interface FoldResult {
  folded: string;
  transforms: Transform[];
  /** Non-ASCII look-alike code points that were folded (for evidence). */
  homoglyphs: number[];
}

/**
 * Curated confusables: letters from other scripts that render like Latin letters in common fonts.
 * Deliberately small (not the full Unicode TR39 table) so ordinary Cyrillic/Greek text is not
 * turned into accidental English.
 */
const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic lowercase
  '\u0430': 'a', '\u0441': 'c', '\u0501': 'd', '\u0435': 'e', '\u04BB': 'h', '\u0456': 'i', '\u0458': 'j',
  '\u043A': 'k', '\u04CF': 'l', '\u043E': 'o', '\u0440': 'p', '\u051B': 'q', '\u0455': 's', '\u0442': 't',
  '\u0443': 'y', '\u051D': 'w', '\u0445': 'x', '\u0432': 'b', '\u043C': 'm', '\u043D': 'h', '\u04AF': 'y',
  // Cyrillic uppercase
  '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E', '\u041D': 'H', '\u0406': 'I', '\u0408': 'J',
  '\u041A': 'K', '\u041C': 'M', '\u041E': 'O', '\u0420': 'P', '\u0405': 'S', '\u0422': 'T', '\u0425': 'X',
  '\u0423': 'Y', '\u04C0': 'I',
  // Greek
  '\u03B1': 'a', '\u03B9': 'i', '\u03BA': 'k', '\u03BD': 'v', '\u03BF': 'o', '\u03C1': 'p', '\u03C4': 't',
  '\u03C5': 'u', '\u03C7': 'x', '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
  '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T',
  '\u03A5': 'Y', '\u03A7': 'X',
  // Armenian
  '\u0585': 'o', '\u057D': 'u', '\u0570': 'h', '\u0578': 'n', '\u0581': 'g', '\u0566': 'q',
  // Latin-adjacent letters that NFKC leaves alone
  '\u0131': 'i', '\u0261': 'g', '\u0251': 'a', '\u026A': 'i',
};

const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };

const LATIN_RE = /\p{Script=Latin}/u;
const LETTER_RE = /\p{L}/u;

function stripInvisible(text: string): string {
  if (!hasInvisible(text)) return text;
  let out = '';
  for (const ch of text) if (!classifyInvisible(ch.codePointAt(0)!)) out += ch;
  return out;
}

function reverseOverrides(text: string): string {
  if (!text.includes('\u202E')) return text;
  return text.replace(/\u202E([^\u202C\u2069]*)/g, (_, seg: string) => [...seg].reverse().join(''));
}

function collapseSpacedLetters(text: string): string {
  // Five or more single letters separated by one space/dot/dash/underscore/asterisk.
  return text.replace(/(?<![\p{L}\p{N}])\p{L}(?:[ ._*-]\p{L}){4,}(?![\p{L}\p{N}])/gu, (m) => m.replace(/[ ._*-]/g, ''));
}

function foldHomoglyphs(text: string, found: number[]): string {
  const letters = text.match(/\p{L}/gu) ?? [];
  const latinShare = letters.length ? letters.filter((c) => LATIN_RE.test(c)).length / letters.length : 0;
  return text.replace(/[\p{L}\p{M}]+/gu, (word) => {
    const chars = [...word];
    const mixed = chars.some((c) => LATIN_RE.test(c)) && chars.some((c) => HOMOGLYPHS[c] !== undefined);
    // A word made entirely of look-alikes is folded only inside mostly-Latin text, so Russian or Greek
    // passages are never rewritten into English.
    const allLookalike = latinShare >= 0.7 && chars.every((c) => HOMOGLYPHS[c] !== undefined);
    if (!mixed && !allLookalike) return word;
    return chars
      .map((c) => {
        const rep = HOMOGLYPHS[c];
        if (rep === undefined) return c;
        found.push(c.codePointAt(0)!);
        return rep;
      })
      .join('');
  });
}

function foldLeet(text: string): string {
  return text.replace(/[\p{L}0-9@$]{3,}/gu, (token) => {
    const letters = [...token].filter((c) => LETTER_RE.test(c)).length;
    if (letters < 2 || !/[0-9@$]/.test(token)) return token;
    // Letters followed only by digits are names and versions (web3, mp3, h264, covid19), not leetspeak.
    if (/^\p{L}+[0-9]+$/u.test(token)) return token;
    return token.replace(/[0-9@$]/g, (c) => LEET[c] ?? c);
  });
}

const sameIgnoringSpaces = (a: string, b: string): boolean => a.replace(/\s+/g, ' ') === b.replace(/\s+/g, ' ');

export function foldForMatching(text: string): FoldResult {
  const transforms: Transform[] = [];
  const homoglyphs: number[] = [];
  const step = (name: Transform, next: string, prev: string): string => {
    if (!sameIgnoringSpaces(next, prev)) transforms.push(name);
    return next;
  };
  let s = text;
  s = step('bidi_reversal', reverseOverrides(s), s);
  s = step('invisible_chars', stripInvisible(s), s);
  s = step('nfkc', s.normalize('NFKC'), s);
  s = step('spaced_letters', collapseSpacedLetters(s), s);
  s = step('homoglyph', foldHomoglyphs(s, homoglyphs), s);
  s = step('leetspeak', foldLeet(s), s);
  return { folded: s, transforms, homoglyphs: [...new Set(homoglyphs)] };
}
