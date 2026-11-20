import { Client } from '@modelcontextprotocol/client';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseHtml } from '../../src/analysis/html-parser.js';
import { aiPromptInjectionDetector } from '../../src/detectors/ai-prompt-injection.js';
import { hiddenContentDetector } from '../../src/detectors/hidden-content.js';
import { bidiOverrideDetector, unicodeObfuscationDetector } from '../../src/detectors/obfuscation.js';
import { spamInjectionDetector } from '../../src/detectors/spam-injection.js';
import { createServer } from '../../src/mcp/server.js';
import type { Finding } from '../../src/types/finding.js';
import type { FetchResult } from '../../src/types/scan.js';
import { randomBase64 } from '../fixtures/obfuscation.js';
import { startFixtureSite, type FixtureSite } from '../fixtures/site.js';
import { ALL_CHECKS, testEnv } from '../helpers/env.js';

const INVISIBLE = /[\p{Cf}\p{Cs}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/u;

let site: FixtureSite;
let env: ReturnType<typeof testEnv>;
beforeAll(async () => {
  site = await startFixtureSite();
  env = testEnv(site.allow);
});
afterAll(async () => site.close());

const scan = (path: string) => env.orchestrator.scanUrl({ url: `${site.site}${path}`, ...ALL_CHECKS });
const of = (fs: Finding[], rule: string) => fs.filter((f) => f.rule_id === rule);
const enc = (f: Finding) => f.evidence[0]!.details?.encoding;

describe('AI-007 invisible Unicode smuggling', () => {
  it('decodes tag, selector and zero-width payloads with content-based severity', async () => {
    const r = await scan('/unicode-smuggling');
    const ai7 = of(r.findings, 'AI-007');
    expect(ai7).toHaveLength(4);
    const byKind = (k: string) => ai7.filter((f) => enc(f) === k);
    expect(byKind('tag_characters')[0]).toMatchObject({ severity: 'high', confidence: 'high' });
    expect(byKind('variation_selectors')[0]!.severity).toBe('critical'); // memory persistence
    const zw = byKind('zero_width_binary');
    expect(zw.map((f) => f.severity).sort()).toEqual(['high', 'low']); // casino spam vs short watermark
    expect(ai7.every((f) => /^U\+/.test(String(f.evidence[0]!.details?.codepoints)))).toBe(true);
    expect(r.risk.overall_risk).toBe('critical');
  });
});

describe('AI-008 obfuscated instructions', () => {
  it('catches homoglyph, fullwidth, leetspeak, spaced, zero-width and reversed variants', async () => {
    const r = await scan('/homoglyph-injection');
    const transforms = of(r.findings, 'AI-008').flatMap((f) => f.evidence[0]!.details?.obfuscation as string[]);
    for (const t of ['homoglyph', 'nfkc', 'leetspeak', 'spaced_letters', 'invisible_chars', 'bidi_reversal']) expect(transforms).toContain(t);
    expect(of(r.findings, 'AI-008')).toHaveLength(6);
    expect(of(r.findings, 'AI-001')).toHaveLength(0); // raw text never matched
  });

  it('feeds folded text into spam rules (look-alike "casino" in a hidden link)', async () => {
    const r = await scan('/homoglyph-injection');
    expect(of(r.findings, 'HID-002')[0]).toMatchObject({ severity: 'critical' });
  });
});

describe('AI-009 encoded payloads', () => {
  it('reports exactly the malicious payloads and skips data URIs, JWTs, hashes, nonces and fonts', async () => {
    const r = await scan('/encoded-payload');
    const ai9 = of(r.findings, 'AI-009');
    expect(ai9).toHaveLength(4);
    expect(ai9.map((f) => (f.evidence[0]!.details?.layers as string[]).join('+')).sort()).toEqual(['base64', 'base64+base64', 'hex', 'percent']);
    expect(ai9.find((f) => /system prompt/.test(f.evidence[0]!.excerpt!))!.severity).toBe('critical');
  });
});

describe('HID-006 bidi overrides', () => {
  it('flags overrides in Latin text, high when the reordered text is an instruction', async () => {
    const r = await scan('/bidi-override');
    expect(of(r.findings, 'HID-006').map((f) => f.severity).sort()).toEqual(['high', 'medium']);
    expect(of(r.findings, 'HID-006').find((f) => f.severity === 'medium')!.evidence[0]!.details?.displayed_as).toBe('exe.png');
  });
});

describe('false-positive guards', () => {
  it.each(['/legit-multilingual', '/legit-cyrillic'])('%s produces no findings at all', async (path) => {
    const r = await scan(path);
    expect(r.findings.map((f) => `${f.rule_id}: ${f.explanation}`)).toEqual([]);
  });

  it.each(['/clean', '/accordion', '/sr-only', '/article-about-injection'])('earlier legitimate page %s gains no new rules', async (path) => {
    const r = await scan(path);
    expect(r.findings.filter((f) => ['AI-007', 'AI-008', 'AI-009', 'HID-006'].includes(f.rule_id))).toEqual([]);
  });
});

describe('output safety over MCP', () => {
  it('no tool result contains invisible characters, even for smuggling pages', async () => {
    const server = createServer(env.config, env.repo);
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const client = new Client({ name: 't', version: '1' });
    await client.connect(ct);
    for (const path of ['/unicode-smuggling', '/homoglyph-injection', '/encoded-payload', '/bidi-override', '/legit-multilingual']) {
      const res = (await client.callTool({ name: 'geo_scan_url', arguments: { url: `${site.site}${path}` } })) as { content: Array<{ text: string }>; structuredContent?: unknown };
      expect(INVISIBLE.test(res.content[0]!.text), path).toBe(false);
      expect(INVISIBLE.test(JSON.stringify(res.structuredContent)), path).toBe(false);
      const scanId = JSON.parse(res.content[0]!.text).scan_id as string;
      for (const format of ['markdown', 'json']) {
        const rep = (await client.callTool({ name: 'geo_get_report', arguments: { scan_id: scanId, format } })) as { content: Array<{ text: string }> };
        expect(INVISIBLE.test(rep.content[0]!.text), `${path} ${format}`).toBe(false);
      }
    }
    await client.close();
  });
});

describe('performance', () => {
  it('analyses a 2 MB page with hundreds of encoded blobs within budget', () => {
    const blobs = Array.from({ length: 400 }, (_, i) => `<div data-v${i}="${randomBase64(150)}">item ${i}</div>`).join('\n');
    const prose = '<p>Acme widgets are precision engineered for industrial use and ship worldwide every day.</p>\n'.repeat(21_000);
    const html = `<html><head><title>Big</title></head><body>${blobs}${prose}</body></html>`;
    expect(html.length).toBeGreaterThan(2_000_000);
    const started = Date.now();
    const page = parseHtml(html, 'https://big.example/');
    const fetch = { body: html } as FetchResult;
    for (const d of [hiddenContentDetector, spamInjectionDetector, bidiOverrideDetector, aiPromptInjectionDetector, unicodeObfuscationDetector]) {
      expect(d.run({ fetch, page, declaredRedirects: [] })).toEqual([]);
    }
    const ms = Date.now() - started;
    expect(ms, `2 MB page analysed in ${ms} ms`).toBeLessThan(2000);
  });
});
