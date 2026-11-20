import type { EvidenceSource } from '../types/finding.js';
import { AI_LINK_RE, extractAiPrefill } from './ai-patterns.js';
import type { PageSnapshot } from './html-parser.js';
import { resolveUrl } from './url-utils.js';

/** Every place on a page whose text an AI system may read, with where it came from. */
export type ChannelKind = 'hidden' | 'comment' | 'attribute' | 'data_attribute' | 'meta' | 'json_ld' | 'title' | 'visible' | 'prefill';

export interface TextChannel {
  kind: ChannelKind;
  source: EvidenceSource;
  location: string;
  text: string;
  hidden: boolean;
}

export interface AiPrefillLink {
  url: URL;
  assistant: string;
  param: string;
  prompt: string;
  text: string;
  location: string;
  source: EvidenceSource;
}

/** Flattens JSON-LD into (path, string) pairs. */
export function flattenStrings(value: unknown, path = '$', out: Array<{ path: string; text: string }> = []): Array<{ path: string; text: string }> {
  if (typeof value === 'string') out.push({ path, text: value });
  else if (Array.isArray(value)) value.forEach((v, i) => flattenStrings(v, `${path}[${i}]`, out));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) flattenStrings(v, `${path}.${k}`, out);
  return out;
}

/** Splits text into sentence-ish chunks so each visible finding has a focused excerpt. */
export function chunks(text: string): string[] {
  return text.split(/(?<=[.!?])\s+(?=[A-Z"'([])/).reduce<string[]>((acc, s) => {
    const last = acc[acc.length - 1];
    if (last !== undefined && last.length < 120) acc[acc.length - 1] = `${last} ${s}`;
    else acc.push(s);
    return acc;
  }, []);
}

/** Links and buttons (onclick/data attributes/scripts) that open an AI assistant with a prefilled prompt. */
export function collectAiPrefills(page: PageSnapshot, body: string): AiPrefillLink[] {
  const candidates: Array<{ href: string; text: string; location: string; source: EvidenceSource }> = page.links
    .filter((l) => l.is_http)
    .map((l) => ({ href: l.href, text: l.text, location: l.selector, source: 'link' as const }));
  for (const m of body.matchAll(AI_LINK_RE)) {
    candidates.push({ href: m[0].replace(/&amp;/g, '&'), text: '', location: 'page source (script, onclick or data attribute)', source: 'html' });
  }
  const seen = new Set<string>();
  const out: AiPrefillLink[] = [];
  for (const c of candidates) {
    const url = resolveUrl(c.href, page.url);
    if (!url || seen.has(url.href)) continue;
    const prefill = extractAiPrefill(url);
    if (!prefill) continue;
    seen.add(url.href);
    out.push({ url, ...prefill, text: c.text, location: c.location, source: c.source });
  }
  return out;
}

export function collectTextChannels(page: PageSnapshot, body: string): TextChannel[] {
  const out: TextChannel[] = [];
  const seen = new Set<string>();
  const add = (c: TextChannel): void => {
    if (!c.text || c.text.trim().length < 3) return;
    const key = `${c.location}\u0000${c.text}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(c);
  };
  if (page.title) add({ kind: 'title', source: 'meta', location: 'head > title', text: page.title, hidden: false });
  for (const h of page.hidden_elements) add({ kind: 'hidden', source: 'html', location: h.selector, text: h.text, hidden: true });
  for (const c of page.comments) add({ kind: 'comment', source: 'comment', location: c.location, text: c.text, hidden: true });
  for (const a of page.attributes) add({ kind: 'attribute', source: 'attribute', location: `${a.selector} [${a.attribute}]`, text: a.value, hidden: a.hidden });
  for (const d of page.data_attributes) add({ kind: 'data_attribute', source: 'attribute', location: `${d.selector} [${d.attribute}]`, text: d.value, hidden: true });
  for (const m of page.meta) add({ kind: 'meta', source: 'meta', location: `${m.selector} (${m.key})`, text: m.content, hidden: true });
  for (const j of page.json_ld) {
    if (j.parsed === undefined) add({ kind: 'json_ld', source: 'json_ld', location: j.selector, text: j.raw, hidden: true });
    else for (const s of flattenStrings(j.parsed)) add({ kind: 'json_ld', source: 'json_ld', location: `${j.selector} ${s.path}`, text: s.text, hidden: true });
  }
  for (const chunk of chunks(page.visible_text)) add({ kind: 'visible', source: 'text', location: 'visible page text', text: chunk, hidden: false });
  for (const p of collectAiPrefills(page, body)) add({ kind: 'prefill', source: p.source, location: `${p.location} → ${p.assistant} prefilled prompt`, text: p.prompt, hidden: true });
  return out;
}
