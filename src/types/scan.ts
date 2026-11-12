import type { Category, Finding, Severity } from './finding.js';

export type ScanProfile = 'quick' | 'standard' | 'deep';

export const REQUEST_CONTEXTS = [
  'desktop_browser',
  'mobile_browser',
  'search_referrer',
  'crawler_ua_simulated',
] as const;
export type RequestContextName = (typeof REQUEST_CONTEXTS)[number];

export interface RedirectHop {
  hop: number;
  url: string;
  status: number;
  location?: string;
  resolved_ip?: string;
  headers: Record<string, string>;
  kind: 'http' | 'refresh_header';
}

export interface DeclaredRedirect {
  kind: 'meta_refresh' | 'javascript';
  target: string;
  location: string;
  excerpt: string;
}

export interface FetchResult {
  requested_url: string;
  final_url: string;
  status: number;
  headers: Record<string, string>;
  content_type: string;
  body: string;
  body_bytes: number;
  truncated: boolean;
  hops: RedirectHop[];
  /** Set when the chain ended without a final 2xx/4xx/5xx page (loop or too many redirects). */
  chain_error?: 'redirect_loop' | 'too_many_redirects';
  elapsed_ms: number;
}

export interface RiskSummary {
  overall_risk: Severity | 'none';
  score: number;
  total_findings: number;
  by_severity: Record<Severity, number>;
  by_category: Partial<Record<Category, number>>;
  headline: string;
}

export interface PageSummary {
  url: string;
  final_url: string;
  status: number;
  content_type: string;
  title?: string;
  meta_description?: string;
  canonical?: string;
  page_hash?: string;
  body_bytes: number;
  truncated: boolean;
  counts: {
    links: number;
    external_links: number;
    scripts: number;
    external_scripts: number;
    iframes: number;
    hidden_elements: number;
    legitimate_hidden_elements: number;
    json_ld_blocks: number;
    html_comments: number;
  };
  external_domains: string[];
  external_script_hosts: string[];
}

export interface ScanReport {
  scan_id: string;
  tool: 'geo_scan_url' | 'geo_trace_redirects';
  target_url: string;
  domain: string;
  scan_profile: ScanProfile;
  request_context: RequestContextName;
  started_at: string;
  completed_at: string;
  status: 'completed' | 'failed';
  error?: { code: string; message: string };
  options: Record<string, unknown>;
  http?: { status: number; content_type: string; headers: Record<string, string>; elapsed_ms: number };
  redirect_chain: RedirectHop[];
  declared_redirects: DeclaredRedirect[];
  page?: PageSummary;
  findings: Finding[];
  risk: RiskSummary;
  notices: string[];
  limitations: string[];
}
