import type { Config } from '../../src/config.js';
import { ScanOrchestrator } from '../../src/scanner/orchestrator.js';
import { openDatabase } from '../../src/storage/database.js';
import { ScansRepository } from '../../src/storage/scans.repository.js';

export function testConfig(fixtureAllow: string[] = []): Config {
  return {
    dbPath: ':memory:',
    logLevel: 'silent',
    fetchTimeoutMs: 5000,
    maxBodyBytes: 512 * 1024,
    retentionDays: 0,
    security: { allowedPorts: new Set([80, 443]), fixtureAllow: new Set(fixtureAllow) },
  };
}

export function testEnv(fixtureAllow: string[] = []) {
  const config = testConfig(fixtureAllow);
  const db = openDatabase(':memory:');
  const repo = new ScansRepository(db);
  const orchestrator = new ScanOrchestrator(config, repo);
  return { config, db, repo, orchestrator };
}

export const ALL_CHECKS = {
  scan_profile: 'standard' as const,
  check_redirects: true,
  check_hidden_content: true,
  check_ai_injection: true,
  render_javascript: false,
};
