/**
 * Encoders used to build obfuscated test content. Everything is generated from escapes so that no
 * invisible or look-alike characters appear literally in the repository.
 */
import { randomBytes } from 'node:crypto';

/** Unicode tag characters mirroring ASCII ("ASCII smuggling"). */
export const tagEncode = (s: string): string => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join('');

/** UTF-8 bytes as variation selectors (VS1–16 = 0–15, VS17–256 = 16–255). */
export const vsEncode = (s: string): string =>
  [...Buffer.from(s, 'utf8')].map((b) => String.fromCodePoint(b < 16 ? 0xfe00 + b : 0xe0100 + b - 16)).join('');

/** Bits as ZERO WIDTH SPACE (0) and ZERO WIDTH NON-JOINER (1). */
export const zwBinary = (s: string): string =>
  [...Buffer.from(s, 'utf8')].map((b) => b.toString(2).padStart(8, '0')).join('').replace(/0/g, '\u200B').replace(/1/g, '\u200C');

const LOOKALIKE: Record<string, string> = { a: '\u0430', o: '\u043E', i: '\u0456', e: '\u0435', c: '\u0441', p: '\u0440' };
/** Replace a, o, i, e, c, p with Cyrillic look-alikes. */
export const homoglyph = (s: string): string => s.replace(/[aoiecp]/g, (c) => LOOKALIKE[c]!);

export const fullwidth = (s: string): string => s.replace(/[!-~]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0));
export const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64');
export const hex = (s: string): string => Buffer.from(s, 'utf8').toString('hex');
export const percentAll = (s: string): string => [...Buffer.from(s, 'utf8')].map((b) => `%${b.toString(16).padStart(2, '0').toUpperCase()}`).join('');
export const reverse = (s: string): string => [...s].reverse().join('');

export const RLO = '\u202E';
export const PDF = '\u202C';

/** A syntactically valid JWT whose payload is readable JSON. */
export const sampleJwt = (): string =>
  [{ alg: 'HS256', typ: 'JWT' }, { sub: 'user-1234', name: 'Acme Customer', iat: 1700000000 }]
    .map((o) => Buffer.from(JSON.stringify(o)).toString('base64url'))
    .concat(randomBytes(32).toString('base64url'))
    .join('.');

/** base64 of bytes that start like a PNG / WOFF2 file. */
export const fakePngBase64 = (): string => Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), randomBytes(120)]).toString('base64');
export const fakeWoff2Base64 = (): string => Buffer.concat([Buffer.from('wOF2'), randomBytes(200)]).toString('base64');
export const randomBase64 = (n = 32): string => randomBytes(n).toString('base64');
export const sha256Hex = (): string => randomBytes(32).toString('hex');
