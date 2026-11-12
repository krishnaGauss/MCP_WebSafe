import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod';
import { matchSpamKeywords } from '../../analysis/keywords.js';
import { findExternalUrlParams, registrableDomain, resolveUrl } from '../../analysis/url-utils.js';
import type { ScanOrchestrator } from '../../scanner/orchestrator.js';
import { REQUEST_CONTEXTS } from '../../types/scan.js';
import { compactFinding, errorResult, jsonResult, READ_ONLY_ANNOTATIONS } from '../tool-helpers.js';

export const traceInput = z.object({
  url: z.string().min(1).max(2048).describe('Absolute http(s) URL whose redirect chain should be reconstructed.'),
  max_redirects: z.number().int().min(1).max(20).default(10),
  request_context: z.enum(REQUEST_CONTEXTS).default('desktop_browser').describe('Request headers preset. Non-browser contexts are simulations.'),
});

export function registerRedirectTrace(server: McpServer, orchestrator: ScanOrchestrator): void {
  server.registerTool(
    'geo_trace_redirects',
    {
      title: 'Trace redirect chain',
      description:
        'Reconstructs the redirect chain of a URL hop by hop (HTTP 3xx and Refresh headers), re-validating every destination against SSRF rules, ' +
        'and reports meta-refresh/JavaScript redirects declared by the final page without executing them. Flags cross-domain redirects, ' +
        'open-redirect patterns, loops and HTTPS downgrades. Read-only: never submits forms or exploits endpoints.',
      inputSchema: traceInput,
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async (args) => {
      try {
        const report = await orchestrator.traceRedirects(args);
        const finalUrl = report.redirect_chain.at(-1)?.url ?? report.target_url;
        const initial = resolveUrl(report.target_url, report.target_url);
        const indicators: string[] = [];
        if (registrableDomain(finalUrl) !== registrableDomain(report.target_url)) indicators.push('final destination is on a different registrable domain');
        if (initial && findExternalUrlParams(initial).length) indicators.push('initial URL carries an external URL in a redirect-style query parameter');
        const spam = matchSpamKeywords(finalUrl);
        if (spam.length) indicators.push(`final URL matches ${spam.map((s) => s.category).join(', ')} keywords`);
        if (report.declared_redirects.length) indicators.push(`final page declares ${report.declared_redirects.length} client-side redirect(s)`);
        return jsonResult({
          untrusted_content_notice: report.notices[0],
          scan_id: report.scan_id,
          initial_url: report.target_url,
          hops: report.redirect_chain,
          hop_count: Math.max(0, report.redirect_chain.length - 1),
          final_url: finalUrl,
          final_status: report.http?.status,
          final_domain: registrableDomain(finalUrl),
          declared_client_redirects: report.declared_redirects,
          suspicious_destination_indicators: indicators,
          findings: report.findings.map(compactFinding),
          risk_summary: report.risk,
          notices: report.notices.slice(1),
        });
      } catch (err) {
        return errorResult(err, 'geo_trace_redirects');
      }
    },
  );
}
