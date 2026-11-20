import type { CallToolResult } from '@modelcontextprotocol/server';
import { toGeoShieldError } from '../errors.js';
import { logger } from '../logger.js';
import { deepStripInvisible, stripInvisible } from '../risk/evidence.js';
import type { Finding } from '../types/finding.js';
import type { ScanReport } from '../types/scan.js';

export const READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
} as const;

export function jsonResult(input: Record<string, unknown>): CallToolResult {
  // Final guard: nothing invisible from a scanned page may reach the agent through a tool result.
  const payload = deepStripInvisible(input);
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
  };
}

/** Converts any thrown error into a structured, understandable MCP tool error. */
export function errorResult(err: unknown, tool: string): CallToolResult {
  const e = toGeoShieldError(err);
  if (e.code === 'INTERNAL_ERROR' || e.code === 'FETCH_FAILED') logger.warn({ tool, err }, 'tool error');
  const payload = deepStripInvisible({ error: e.toJSON() });
  return { isError: true, content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], structuredContent: payload };
}

/** A tool-response view of a finding: full metadata, first few evidence items. */
export function compactFinding(f: Finding): Record<string, unknown> {
  return {
    id: f.id,
    rule_id: f.rule_id,
    category: f.category,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    explanation: f.explanation,
    observed_behaviour: f.observed_behaviour,
    evidence: f.evidence.slice(0, 3),
    ...(f.evidence.length > 3 ? { more_evidence: `${f.evidence.length - 3} more item(s) — use geo_get_report` } : {}),
    recommendation: f.recommendation,
    false_positive_considerations: f.false_positive_considerations,
  };
}

export function scanResponse(report: ScanReport): Record<string, unknown> {
  const findings = report.findings;
  const byCategory = (prefix: string[]): Record<string, unknown>[] =>
    findings.filter((f) => prefix.some((p) => f.rule_id.startsWith(p))).map(compactFinding);
  return {
    untrusted_content_notice: report.notices[0],
    scan_id: report.scan_id,
    target_url: report.target_url,
    final_url: report.page?.final_url ?? report.redirect_chain.at(-1)?.url ?? report.target_url,
    http: report.http,
    request_context: report.request_context,
    risk_summary: report.risk,
    redirect_chain: report.redirect_chain,
    declared_client_redirects: report.declared_redirects,
    redirect_findings: byCategory(['RED']),
    hidden_content_findings: byCategory(['HID', 'SPM', 'MET']),
    ai_injection_findings: byCategory(['AI']),
    page: report.page,
    notices: report.notices.slice(1),
    limitations: report.limitations,
    next_steps: `Full evidence and remediation: geo_get_report { "scan_id": "${report.scan_id}", "format": "markdown" }`,
  };
}

/** Plain-text tool result (markdown reports), with invisible characters removed. */
export function textResult(text: string): CallToolResult {
  return { content: [{ type: 'text', text: text.split('\n').map(stripInvisible).join('\n') }] };
}
