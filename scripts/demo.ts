/**
 * End-to-end demo: starts the local fixture site, launches the BUILT server (dist/index.js)
 * over real stdio exactly as Claude would, and calls each tool.
 *   npm run build && npm run demo
 * Pass a public URL to also scan it:  npm run demo -- https://example.com
 */
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { startFixtureSite } from '../tests/fixtures/site.ts';

const site = await startFixtureSite();
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ['dist/index.js'],
  env: {
    ...process.env,
    GEO_SHIELD_DB_PATH: path.join(os.tmpdir(), `geo-shield-demo-${process.pid}.db`),
    GEO_SHIELD_FIXTURE_ALLOW: site.allow.join(','),
    GEO_SHIELD_LOG_LEVEL: 'warn',
  } as Record<string, string>,
  stderr: 'ignore',
});
const client = new Client({ name: 'geo-shield-demo', version: '0.1.0' });
await client.connect(transport);

const call = async (name: string, args: Record<string, unknown>) => {
  const r = (await client.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
  return { isError: !!r.isError, text: r.content[0]!.text };
};
const brief = (text: string) => {
  const p = JSON.parse(text);
  if (p.error) return `ERROR ${p.error.code}: ${p.error.message}`;
  const fs = [...(p.redirect_findings ?? []), ...(p.hidden_content_findings ?? []), ...(p.ai_injection_findings ?? []), ...(p.findings ?? [])];
  return `${p.scan_id} risk=${p.risk_summary.overall_risk} score=${p.risk_summary.score}\n` +
    fs.map((f: any) => `    ${f.rule_id} [${f.severity}/${f.confidence}] ${f.title}`).join('\n'); // eslint-disable-line @typescript-eslint/no-explicit-any
};

console.log('tools:', (await client.listTools()).tools.map((t) => t.name).join(', '));
for (const p of ['/clean', '/accordion', '/white-links', '/ai-hidden', '/ai-summarize', '/spam-page', '/ref-redirect']) {
  console.log(`\ngeo_scan_url ${p}\n  ${brief((await call('geo_scan_url', { url: site.site + p })).text)}`);
}
const trace = await call('geo_trace_redirects', { url: `${site.site}/redirect?url=${encodeURIComponent(site.evil + '/casino')}` });
const t = JSON.parse(trace.text);
console.log(`\ngeo_trace_redirects /redirect?url=<external>\n  hops: ${t.hops.map((h: { status: number; url: string }) => `${h.status} ${h.url}`).join(' -> ')}\n  indicators: ${t.suspicious_destination_indicators.join('; ')}\n  ${brief(trace.text)}`);
console.log(`\ngeo_scan_url http://169.254.169.254/  ->  ${brief((await call('geo_scan_url', { url: 'http://169.254.169.254/latest/meta-data/' })).text)}`);

const id = JSON.parse((await call('geo_scan_url', { url: `${site.site}/ai-summarize` })).text).scan_id;
const md = await call('geo_get_report', { scan_id: id, format: 'markdown' });
console.log(`\ngeo_get_report ${id} (markdown, first 40 lines)\n${md.text.split('\n').slice(0, 40).join('\n')}`);

for (const url of process.argv.slice(2)) console.log(`\ngeo_scan_url ${url}\n  ${brief((await call('geo_scan_url', { url })).text)}`);

await client.close();
await site.close();
