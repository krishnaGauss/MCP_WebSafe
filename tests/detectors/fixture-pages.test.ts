import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Finding } from '../../src/types/finding.js';
import type { RequestContextName } from '../../src/types/scan.js';
import { startFixtureSite, type FixtureSite } from '../fixtures/site.js';
import { ALL_CHECKS, testEnv } from '../helpers/env.js';

let site: FixtureSite;
let env: ReturnType<typeof testEnv>;

beforeAll(async () => {
  site = await startFixtureSite();
  env = testEnv(site.allow);
});
afterAll(async () => site.close());

async function scan(path: string, request_context: RequestContextName = 'desktop_browser') {
  return env.orchestrator.scanUrl({ url: `${site.site}${path}`, ...ALL_CHECKS, request_context });
}
const rules = (fs: Finding[]) => fs.map((f) => f.rule_id);
const actionable = (fs: Finding[]) => fs.filter((f) => f.severity !== 'informational');
const get = (fs: Finding[], id: string) => fs.find((f) => f.rule_id === id)!;

describe('legitimate pages produce no actionable findings', () => {
  it.each(['/clean', '/accordion', '/sr-only', '/old-page'])('%s', async (path) => {
    const r = await scan(path);
    expect(r.status).toBe('completed');
    expect(actionable(r.findings), JSON.stringify(r.findings.map((f) => [f.rule_id, f.explanation]))).toEqual([]);
    expect(r.risk.overall_risk).toBe('none');
  });

  it('legitimate hidden UI elements are counted but not flagged', async () => {
    const r = await scan('/accordion');
    expect(r.page!.counts.hidden_elements).toBeGreaterThanOrEqual(4);
    expect(r.page!.counts.legitimate_hidden_elements).toBe(r.page!.counts.hidden_elements);
  });

  it('same-site migration redirect is traced but not flagged', async () => {
    const r = await scan('/old-page');
    expect(r.redirect_chain.map((h) => h.status)).toEqual([301, 200]);
    expect(r.page!.final_url).toBe(`${site.site}/new-page`);
  });
});

describe('hidden content', () => {
  it('detects white-on-white casino links (HID-002, critical)', async () => {
    const r = await scan('/white-links');
    const f = get(r.findings, 'HID-002');
    expect(f).toBeDefined();
    expect(f.severity).toBe('critical');
    expect(f.evidence[0]!.visibility).toMatch(/colour matches/);
    expect(f.evidence[0]!.location).toMatch(/div/);
    expect(JSON.stringify(f.evidence[0]!.details)).toContain('/casino');
  });

  it('detects off-screen pharma text (HID-003, high)', async () => {
    const r = await scan('/offscreen');
    const f = get(r.findings, 'HID-003');
    expect(f.severity).toBe('high');
    expect(f.evidence[0]!.excerpt).toMatch(/viagra/i);
  });
});

describe('spam injection and metadata', () => {
  it('detects a visible injected casino link (SPM-001)', async () => {
    const r = await scan('/casino-link');
    const f = get(r.findings, 'SPM-001');
    expect(f).toBeDefined();
    expect(f.confidence).toBe('medium');
    expect(f.explanation).toMatch(/does not appear to be about this topic/);
  });

  it('detects a hidden external iframe (SPM-002, high)', async () => {
    const r = await scan('/iframe');
    expect(get(r.findings, 'SPM-002').severity).toBe('high');
  });

  it('detects hijacked metadata on a spam page (MET-001, high)', async () => {
    const r = await scan('/spam-page');
    const f = get(r.findings, 'MET-001');
    expect(f.severity).toBe('high');
    expect(f.evidence.some((e) => e.location.includes('title'))).toBe(true);
  });

  it('detects obfuscated inline scripts (SPM-003)', async () => {
    const r = await scan('/obfuscated');
    expect(rules(r.findings)).toContain('SPM-003');
  });
});

describe('redirects', () => {
  it('detects an open redirect to an external domain (RED-002 + RED-001)', async () => {
    const r = await scan(`/redirect?url=${encodeURIComponent(`${site.evil}/casino`)}`);
    expect(rules(r.findings)).toEqual(expect.arrayContaining(['RED-002', 'RED-001']));
    expect(get(r.findings, 'RED-002').confidence).toBe('high');
    expect(get(r.findings, 'RED-001').severity).toBe('high'); // destination matches casino keywords
  });

  it('detects user-agent conditional redirect only under the crawler simulation', async () => {
    const normal = await scan('/ua-redirect');
    expect(rules(normal.findings)).not.toContain('RED-001');
    const crawler = await scan('/ua-redirect', 'crawler_ua_simulated');
    expect(rules(crawler.findings)).toContain('RED-001');
    expect(crawler.notices.join(' ')).toMatch(/simulation/i);
  });

  it('detects referrer-conditional redirect logic in page script (RED-008)', async () => {
    const r = await scan('/ref-redirect');
    const f = get(r.findings, 'RED-008');
    expect(f.severity).toBe('high');
    expect(rules(r.findings)).toContain('RED-004');
    const fromSearch = await scan('/ref-redirect', 'search_referrer');
    expect(rules(fromSearch.findings)).toContain('RED-001');
  });

  it('detects zero-delay meta refresh to external domain (RED-004)', async () => {
    const r = await scan('/meta-refresh');
    const f = get(r.findings, 'RED-004');
    expect(f.confidence).toBe('high');
    expect(f.severity).toBe('high');
  });

  it('detects redirect loops (RED-005)', async () => {
    const r = await scan('/loop');
    expect(rules(r.findings)).toContain('RED-005');
  });

  it('detects deceptive link text (RED-006)', async () => {
    const r = await scan('/deceptive');
    const f = get(r.findings, 'RED-006');
    expect(f.explanation).toMatch(/paypal\.com/);
  });
});

describe('AI prompt injection', () => {
  it('detects hidden instructions, comments, alt text and JSON-LD', async () => {
    const r = await scan('/ai-hidden');
    const hidden = get(r.findings, 'AI-001');
    expect(hidden.severity).toBe('high');
    expect(hidden.confidence).toBe('high');
    const channels = r.findings.filter((f) => f.rule_id === 'AI-002').map((f) => f.evidence[0]!.source);
    expect(channels).toEqual(expect.arrayContaining(['comment', 'attribute', 'json_ld']));
    // Persistence ("remember ... in all future conversations") raises severity.
    const comment = r.findings.find((f) => f.rule_id === 'AI-002' && f.evidence[0]!.source === 'comment')!;
    expect(comment.severity).toBe('critical');
    // Hidden AI text must not be double-reported as generic hidden text.
    expect(rules(r.findings)).not.toContain('HID-001');
  });

  it('detects manipulative "Summarise with AI" links and leaves benign ones informational', async () => {
    const r = await scan('/ai-summarize');
    const bad = r.findings.filter((f) => f.rule_id === 'AI-004');
    expect(bad).toHaveLength(2);
    const chatgpt = bad.find((f) => JSON.stringify(f.evidence).includes('ChatGPT'))!;
    expect(chatgpt.severity).toBe('critical'); // memory persistence
    expect(chatgpt.evidence[0]!.excerpt).toMatch(/trusted source/);
    expect(bad.some((f) => f.evidence[0]!.location.includes('page source'))).toBe(true); // onclick button
    const benign = r.findings.filter((f) => f.rule_id === 'AI-005');
    expect(benign).toHaveLength(1);
    expect(JSON.stringify(benign[0]!.evidence)).toContain('Claude');
  });

  it('treats an article about prompt injection as low risk', async () => {
    const r = await scan('/article-about-injection');
    const f = get(r.findings, 'AI-003');
    expect(f.severity).toBe('low');
    expect(f.confidence).toBe('low');
    expect(r.findings.filter((x) => x.severity !== 'low' && x.severity !== 'informational')).toEqual([]);
  });
});

describe('report integrity', () => {
  it('every finding carries id, rule, severity, confidence, evidence and remediation', async () => {
    const r = await scan('/ai-hidden');
    for (const f of r.findings) {
      expect(f.id).toMatch(new RegExp(`^${r.scan_id}-F\\d{3}$`));
      expect(f.severity).toBeTruthy();
      expect(f.confidence).toBeTruthy();
      expect(f.evidence.length).toBeGreaterThan(0);
      expect(f.recommendation.length).toBeGreaterThan(10);
      expect(f.false_positive_considerations.length).toBeGreaterThan(3);
    }
    expect(env.repo.get(r.scan_id)?.findings.length).toBe(r.findings.length);
  });

  it('excerpts are sanitised and truncated', async () => {
    const r = await scan('/ai-hidden');
    for (const f of r.findings) for (const e of f.evidence) if (e.excerpt) expect(e.excerpt.length).toBeLessThanOrEqual(300);
  });

  it('non-HTML responses skip content detectors with a notice', async () => {
    const r = await scan('/json');
    expect(r.findings).toEqual([]);
    expect(r.notices.join(' ')).toMatch(/not HTML/);
  });

  it('render_javascript returns an explicit not-supported notice', async () => {
    const r = await env.orchestrator.scanUrl({ url: `${site.site}/clean`, ...ALL_CHECKS, render_javascript: true });
    expect(r.notices.join(' ')).toMatch(/not implemented/);
  });
});
