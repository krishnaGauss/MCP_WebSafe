import path from 'node:path';

export interface SecurityPolicy {
  /** Destination ports allowed for scanning. */
  allowedPorts: Set<number>;
  /**
   * TEST ONLY. "host:port" pairs (loopback) that may be fetched, for the local fixture server.
   * Empty in normal operation, which means no loopback/private address is ever reachable.
   */
  fixtureAllow: Set<string>;
}

export interface Config {
  dbPath: string;
  logLevel: string;
  fetchTimeoutMs: number;
  maxBodyBytes: number;
  retentionDays: number;
  security: SecurityPolicy;
}

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function listEnv(name: string): string[] {
  return (process.env[name] ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function loadConfig(): Config {
  const ports = new Set<number>([80, 443]);
  for (const p of listEnv('GEO_SHIELD_ALLOWED_PORTS')) {
    const n = Number.parseInt(p, 10);
    if (n > 0 && n < 65536) ports.add(n);
  }
  return {
    dbPath: path.resolve(process.env.GEO_SHIELD_DB_PATH ?? path.join(process.cwd(), 'data', 'geo-shield.db')),
    logLevel: process.env.GEO_SHIELD_LOG_LEVEL ?? 'info',
    fetchTimeoutMs: intEnv('GEO_SHIELD_FETCH_TIMEOUT_MS', 10_000),
    maxBodyBytes: intEnv('GEO_SHIELD_MAX_BODY_BYTES', 2 * 1024 * 1024),
    retentionDays: intEnv('GEO_SHIELD_RETENTION_DAYS', 30),
    security: {
      allowedPorts: ports,
      fixtureAllow: new Set(listEnv('GEO_SHIELD_FIXTURE_ALLOW').map((s) => s.toLowerCase())),
    },
  };
}
