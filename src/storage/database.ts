import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const MIGRATIONS: string[] = [
  `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS scans (
     id TEXT PRIMARY KEY,
     tool TEXT NOT NULL,
     target_url TEXT NOT NULL,
     domain TEXT NOT NULL,
     started_at TEXT NOT NULL,
     completed_at TEXT,
     scan_profile TEXT NOT NULL,
     scan_status TEXT NOT NULL,
     overall_risk TEXT,
     summary TEXT,
     report_json TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain, started_at);
   CREATE TABLE IF NOT EXISTS pages (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
     url TEXT NOT NULL,
     final_url TEXT NOT NULL,
     status_code INTEGER,
     page_hash TEXT,
     text_fingerprint TEXT,
     title TEXT,
     canonical_url TEXT,
     fetched_at TEXT NOT NULL
   );
   CREATE TABLE IF NOT EXISTS findings (
     id TEXT PRIMARY KEY,
     scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
     page_id INTEGER REFERENCES pages(id) ON DELETE CASCADE,
     rule_id TEXT NOT NULL,
     category TEXT NOT NULL,
     severity TEXT NOT NULL,
     confidence TEXT NOT NULL,
     title TEXT NOT NULL,
     description TEXT NOT NULL,
     recommendation TEXT NOT NULL,
     evidence_json TEXT NOT NULL
   );
   CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
   CREATE TABLE IF NOT EXISTS redirect_hops (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
     source_url TEXT NOT NULL,
     destination_url TEXT,
     status_code INTEGER NOT NULL,
     hop_number INTEGER NOT NULL
   );`,
];

export function openDatabase(dbPath: string): DatabaseSync {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec('CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);');
  const row = db.prepare('SELECT MAX(version) AS v FROM schema_version').get() as { v: number | null } | undefined;
  const current = row?.v ?? 0;
  for (let i = current; i < MIGRATIONS.length; i++) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[i]!);
      db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(i + 1);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }
  return db;
}
