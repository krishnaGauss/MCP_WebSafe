import { Client } from '@modelcontextprotocol/client';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer } from '../../src/mcp/server.js';
import { startFixtureSite, type FixtureSite } from '../fixtures/site.js';
import { testEnv } from '../helpers/env.js';

let site: FixtureSite;
let client: Client;

type ToolResult = { isError?: boolean; content: Array<{ type: string; text?: string }>; structuredContent?: Record<string, unknown> };
const call = async (name: string, args: Record<string, unknown>) => (await client.callTool({ name, arguments: args })) as unknown as ToolResult;
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- test payloads are arbitrary JSON
const payload = (r: ToolResult) => JSON.parse(r.content[0]!.text!) as Record<string, any>;

beforeAll(async () => {
  site = await startFixtureSite();
  const env = testEnv(site.allow);
  const server = createServer(env.config, env.repo);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: 'test-client', version: '1.0.0' });
  await client.connect(clientTransport);
});
afterAll(async () => {
  await client.close();
  await site.close();
});

describe('MCP server', () => {
  it('lists the three Milestone-1 tools with read-only annotations', async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['geo_get_report', 'geo_scan_url', 'geo_trace_redirects']);
    for (const t of tools) expect(t.annotations?.readOnlyHint).toBe(true);
  });

  it('geo_scan_url returns evidence-based findings grouped by category', async () => {
    const res = await call('geo_scan_url', { url: `${site.site}/ai-summarize` });
    expect(res.isError).toBeFalsy();
    const p = payload(res);
    expect(p.untrusted_content_notice).toMatch(/untrusted data/);
    expect(p.scan_id).toMatch(/^scan_/);
    expect(p.ai_injection_findings.map((f: { rule_id: string }) => f.rule_id)).toContain('AI-004');
    expect(p.risk_summary.overall_risk).toBe('critical');
    expect(res.structuredContent?.scan_id).toBe(p.scan_id);
  });

  it('geo_scan_url respects check toggles', async () => {
    const p = payload(await call('geo_scan_url', { url: `${site.site}/ai-hidden`, check_ai_injection: false }));
    expect(p.ai_injection_findings).toEqual([]);
  });

  it('geo_trace_redirects reconstructs hops and flags the external destination', async () => {
    const target = `${site.site}/redirect?url=${encodeURIComponent(`${site.evil}/casino`)}`;
    const p = payload(await call('geo_trace_redirects', { url: target }));
    expect(p.hops).toHaveLength(2);
    expect(p.hops[0].status).toBe(302);
    expect(p.final_url).toBe(`${site.evil}/casino`);
    expect(p.suspicious_destination_indicators.join(' ')).toMatch(/different registrable domain/);
    expect(p.findings.map((f: { rule_id: string }) => f.rule_id)).toEqual(expect.arrayContaining(['RED-001', 'RED-002']));
  });

  it('geo_get_report returns markdown and json for a stored scan', async () => {
    const { scan_id } = payload(await call('geo_scan_url', { url: `${site.site}/white-links` }));
    const md = await call('geo_get_report', { scan_id, format: 'markdown' });
    expect(md.content[0]!.text).toMatch(/# GEO Integrity Report/);
    expect(md.content[0]!.text).toMatch(/HID-002/);
    const json = payload(await call('geo_get_report', { scan_id, format: 'json' }));
    expect(json.findings.length).toBeGreaterThan(0);
    expect(json.findings[0].evidence.length).toBeGreaterThan(0);
  });

  it('returns structured errors for blocked destinations, bad input and unknown scans', async () => {
    const blocked = await call('geo_scan_url', { url: 'http://169.254.169.254/latest/meta-data/' });
    expect(blocked.isError).toBe(true);
    expect(payload(blocked).error.code).toBe('BLOCKED_DESTINATION');

    const redirectBlocked = await call('geo_trace_redirects', { url: `${site.site}/redirect-to-private` });
    expect(payload(redirectBlocked).error.code).toBe('BLOCKED_DESTINATION');
    expect(payload(redirectBlocked).error.details.redirect_chain).toHaveLength(1);

    const missing = await call('geo_get_report', { scan_id: 'scan_20260101000000_deadbeef' });
    expect(payload(missing).error.code).toBe('NOT_FOUND');

    const invalid = await call('geo_get_report', { scan_id: 'nope' });
    expect(invalid.isError).toBe(true);
  });

  it('exposes taxonomy, rules and scan resources', async () => {
    const tax = await client.readResource({ uri: 'geo://taxonomy' });
    expect(JSON.parse((tax.contents[0] as { text: string }).text).categories.length).toBeGreaterThan(5);
    const rule = await client.readResource({ uri: 'geo://rules/AI-004' });
    expect(JSON.parse((rule.contents[0] as { text: string }).text).rule_id).toBe('AI-004');
    const { scan_id } = payload(await call('geo_scan_url', { url: `${site.site}/clean` }));
    const scan = await client.readResource({ uri: `geo://scan/${scan_id}` });
    expect(JSON.parse((scan.contents[0] as { text: string }).text).scan_id).toBe(scan_id);
    const templates = await client.listResourceTemplates();
    expect(templates.resourceTemplates.map((t) => t.uriTemplate)).toContain('geo://scan/{scan_id}');
  });

  it('exposes investigation prompts that warn about untrusted content', async () => {
    const { prompts } = await client.listPrompts();
    expect(prompts.map((p) => p.name).sort()).toEqual(['investigate_ai_injection', 'investigate_redirect', 'review_scan_findings']);
    const p = await client.getPrompt({ name: 'investigate_ai_injection', arguments: { url: 'https://example.com' } });
    expect((p.messages[0]!.content as { text: string }).text).toMatch(/untrusted data/);
  });
});
