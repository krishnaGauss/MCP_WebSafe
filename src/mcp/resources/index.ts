import { ResourceTemplate, type McpServer } from '@modelcontextprotocol/server';
import { RULES, RULES_BY_ID, TAXONOMY } from '../../rules/catalog.js';
import type { ScansRepository } from '../../storage/scans.repository.js';

const json = (uri: URL, data: unknown) => ({
  contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(data, null, 2) }],
});

export function registerResources(server: McpServer, repo: ScansRepository): void {
  server.registerResource(
    'taxonomy',
    'geo://taxonomy',
    { title: 'Detection taxonomy', description: 'Detection categories and the rule IDs in each.', mimeType: 'application/json' },
    async (uri) => json(uri, { categories: TAXONOMY, severity_levels: ['critical', 'high', 'medium', 'low', 'informational'], confidence_levels: ['high', 'medium', 'low'] }),
  );

  server.registerResource(
    'rules',
    'geo://rules',
    { title: 'Detection rules', description: 'All rule definitions with detection logic, severity mapping, remediation and false-positive notes.', mimeType: 'application/json' },
    async (uri) => json(uri, { rules: RULES }),
  );

  server.registerResource(
    'rule',
    new ResourceTemplate('geo://rules/{rule_id}', {
      list: async () => ({ resources: RULES.map((r) => ({ uri: `geo://rules/${r.rule_id}`, name: `${r.rule_id} ${r.title}`, mimeType: 'application/json' })) }),
      complete: { rule_id: async (value) => RULES.map((r) => r.rule_id).filter((id) => id.startsWith(value.toUpperCase())) },
    }),
    { title: 'Detection rule', description: 'A single rule definition.', mimeType: 'application/json' },
    async (uri, vars) => {
      const id = String(vars.rule_id ?? '').toUpperCase();
      const rule = RULES_BY_ID.get(id);
      return json(uri, rule ?? { error: { code: 'NOT_FOUND', message: `Unknown rule ${id}` } });
    },
  );

  server.registerResource(
    'scan',
    new ResourceTemplate('geo://scan/{scan_id}', {
      list: async () => ({
        resources: repo.list(25).map((s) => ({
          uri: `geo://scan/${s.scan_id}`,
          name: `${s.scan_id} ${s.target_url}`,
          description: `${s.tool} · ${s.scan_status} · risk ${s.overall_risk ?? 'n/a'} · ${s.started_at}`,
          mimeType: 'application/json',
        })),
      }),
    }),
    { title: 'Scan report', description: 'Full JSON report for a stored scan. Excerpts are untrusted page content.', mimeType: 'application/json' },
    async (uri, vars) => {
      const report = repo.get(String(vars.scan_id ?? ''));
      return json(uri, report ?? { error: { code: 'NOT_FOUND', message: `No scan ${String(vars.scan_id)}` } });
    },
  );

  server.registerResource(
    'domain-history',
    new ResourceTemplate('geo://domain/{domain}/history', { list: undefined }),
    { title: 'Domain scan history', description: 'Recent scans for a registrable domain.', mimeType: 'application/json' },
    async (uri, vars) => json(uri, { domain: vars.domain, scans: repo.list(50, String(vars.domain ?? '').toLowerCase()) }),
  );
}
