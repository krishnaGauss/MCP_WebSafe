import { isReadableText } from './unicode-smuggling.js';

/**
 * Finds encoded blobs (base64, hex, percent-encoding, JS escapes) and decodes the ones that turn into
 * readable text. Decoding alone is never a finding: callers only report a payload whose decoded text
 * matches instruction or spam patterns.
 */
export type PayloadEncoding = 'base64' | 'hex' | 'percent' | 'js_escape';

export interface DecodedPayload {
  encoding: PayloadEncoding;
  /** Encodings peeled, outermost first (e.g. ["base64","base64"] for double encoding). */
  layers: PayloadEncoding[];
  /** Start of the encoded blob in the scanned text. */
  index: number;
  /** The encoded blob, truncated. */
  raw: string;
  decoded: string;
}

/** Shared per-page limits so pages full of blobs cannot slow a scan down. */
export interface DecodeBudget {
  remaining: number;
  deadline: number;
}

export const newDecodeBudget = (blobs = 200, ms = 400): DecodeBudget => ({ remaining: blobs, deadline: Date.now() + ms });

const MAX_ENCODED = 8192;
const MAX_DECODED = 4096;
const MAX_DEPTH = 2;

/** Leading bytes of binary formats that are routinely base64-embedded (images, fonts, archives, PDF). */
const BINARY_MAGIC: number[][] = [
  [0x89, 0x50, 0x4e, 0x47], // PNG
  [0xff, 0xd8, 0xff], // JPEG
  [0x47, 0x49, 0x46, 0x38], // GIF
  [0x52, 0x49, 0x46, 0x46], // RIFF (WebP, WAV)
  [0x77, 0x4f, 0x46, 0x46], // WOFF
  [0x77, 0x4f, 0x46, 0x32], // WOFF2
  [0x00, 0x01, 0x00, 0x00], // TTF
  [0x4f, 0x54, 0x54, 0x4f], // OTF
  [0x25, 0x50, 0x44, 0x46], // PDF
  [0x50, 0x4b, 0x03, 0x04], // ZIP
  [0x1f, 0x8b], // gzip
];

const isBinaryFormat = (buf: Buffer): boolean => BINARY_MAGIC.some((sig) => sig.every((b, i) => buf[i] === b));

const utf8 = new TextDecoder('utf-8', { fatal: true });
function asText(buf: Buffer): string | undefined {
  if (buf.length < 4 || isBinaryFormat(buf)) return undefined;
  try {
    const s = utf8.decode(buf.subarray(0, MAX_DECODED));
    return isReadableText(s, 4) ? s : undefined;
  } catch {
    return undefined;
  }
}

// '=' may precede a blob (key=VALUE) since base64 only uses it as trailing padding.
const B64_RE = /(?<![A-Za-z0-9+/_.-])(?:[A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9_-]{24,})(?![A-Za-z0-9+/=_.-])/g;
const HEX_RE = /(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])/g;
const PERCENT_RE = /(?:%[0-9a-fA-F]{2}[^%\s"'<>]{0,3}){6,}/g;
const JS_ESCAPE_RE = /(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){6,}/g;
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

function decodeBase64(s: string): string | undefined {
  const clean = s.replace(/=+$/, '');
  if (clean.length % 4 === 1) return undefined;
  // Long runs of letters only (identifiers, words) are almost never real base64.
  if (/^[A-Za-z]+$/.test(clean) && !/[A-Z].*[a-z].*[A-Z]/.test(clean)) return undefined;
  return asText(Buffer.from(clean.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}

function decodeHex(s: string): string | undefined {
  return asText(Buffer.from(s, 'hex'));
}

function decodePercent(s: string): string | undefined {
  try {
    const d = decodeURIComponent(s);
    return d !== s && isReadableText(d, 4) ? d : undefined;
  } catch {
    return undefined;
  }
}

function decodeJsEscape(s: string): string | undefined {
  const d = s
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  return isReadableText(d, 4) ? d : undefined;
}

const DECODERS: Array<{ encoding: PayloadEncoding; re: RegExp; decode: (s: string) => string | undefined }> = [
  { encoding: 'js_escape', re: JS_ESCAPE_RE, decode: decodeJsEscape },
  { encoding: 'percent', re: PERCENT_RE, decode: decodePercent },
  { encoding: 'hex', re: HEX_RE, decode: decodeHex },
  { encoding: 'base64', re: B64_RE, decode: decodeBase64 },
];

function excluded(text: string, index: number, blob: string, jwtSpans: Array<[number, number]>): boolean {
  if (/data:[^,\s]{0,100};base64,$/i.test(text.slice(Math.max(0, index - 120), index))) return true;
  if (jwtSpans.some(([a, b]) => index >= a && index < b)) return true;
  // Blobs inside URLs/paths (e.g. long slugs) are not payloads.
  if (/^[a-z0-9-]+$/.test(blob) && blob.includes('-')) return true;
  return false;
}

export function findEncodedPayloads(text: string, budget: DecodeBudget = newDecodeBudget(), depth = 0, layers: PayloadEncoding[] = []): DecodedPayload[] {
  const out: DecodedPayload[] = [];
  if (depth >= MAX_DEPTH || text.length < 24) return out;
  const jwtSpans: Array<[number, number]> = [...text.matchAll(JWT_RE)].map((m) => [m.index!, m.index! + m[0].length]);
  const claimed: Array<[number, number]> = [];
  for (const { encoding, re, decode } of DECODERS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      if (budget.remaining <= 0 || Date.now() > budget.deadline) return out;
      const blob = m[0];
      const start = m.index;
      if (claimed.some(([a, b]) => start >= a && start < b)) continue;
      if (blob.length > MAX_ENCODED || excluded(text, start, blob, jwtSpans)) continue;
      budget.remaining--;
      const decoded = decode(blob);
      if (!decoded) continue;
      claimed.push([start, start + blob.length]);
      const chain = [...layers, encoding];
      out.push({ encoding, layers: chain, index: start, raw: blob.length > 120 ? `${blob.slice(0, 117)}…` : blob, decoded });
      // Peel nested encodings (base64 of base64, hex of base64, ...).
      for (const inner of findEncodedPayloads(decoded, budget, depth + 1, chain)) out.push({ ...inner, index: start });
    }
  }
  return out;
}
