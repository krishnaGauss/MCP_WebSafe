import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { loadConfig } from './config.js';
import { logger } from './logger.js';
import { createServer } from './mcp/server.js';
import { openDatabase } from './storage/database.js';
import { ScansRepository } from './storage/scans.repository.js';

function main(): void {
  const config = loadConfig();
  const db = openDatabase(config.dbPath);
  const repo = new ScansRepository(db);
  const purged = repo.purgeOlderThan(config.retentionDays);
  if (config.security.fixtureAllow.size > 0) {
    logger.warn({ allow: [...config.security.fixtureAllow] }, 'GEO_SHIELD_FIXTURE_ALLOW is set: loopback test addresses are reachable. Do not use in normal operation.');
  }
  logger.info({ db: config.dbPath, purged }, 'GEO Shield MCP starting on stdio');
  const handle = serveStdio(() => createServer(config, repo));

  const shutdown = async (): Promise<void> => {
    await handle.close().catch(() => undefined);
    db.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());
}

try {
  main();
} catch (err) {
  logger.fatal({ err }, 'failed to start');
  process.exit(1);
}
