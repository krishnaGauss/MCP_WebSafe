import type { DatabaseSync } from 'node:sqlite';
import type { PageSnapshot } from '../analysis/html-parser.js';
import type { ScanReport } from '../types/scan.js';

export interface ScanListItem {
  scan_id: string;
  tool: string;
  target_url: string;
  domain: string;
  started_at: string;
  scan_status: string;
  overall_risk: string | null;
}

export class ScansRepository {
  constructor(private readonly db: DatabaseSync) {}

  save(report: ScanReport, page?: Pick<PageSnapshot, 'page_hash' | 'text_fingerprint'>): void {
    const db = this.db;
    db.exec('BEGIN');
    try {
      db.prepare(
        `INSERT OR REPLACE INTO scans (id, tool, target_url, domain, started_at, completed_at, scan_profile, scan_status, overall_risk, summary, report_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        report.scan_id, report.tool, report.target_url, report.domain, report.started_at, report.completed_at,
        report.scan_profile, report.status, report.risk.overall_risk, report.risk.headline, JSON.stringify(report),
      );
      let pageId: number | bigint | null = null;
      if (report.page) {
        const res = db.prepare(
          `INSERT INTO pages (scan_id, url, final_url, status_code, page_hash, text_fingerprint, title, canonical_url, fetched_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          report.scan_id, report.page.url, report.page.final_url, report.page.status, page?.page_hash ?? null,
          page?.text_fingerprint ?? null, report.page.title ?? null, report.page.canonical ?? null, report.completed_at,
        );
        pageId = res.lastInsertRowid;
      }
      const insFinding = db.prepare(
        `INSERT INTO findings (id, scan_id, page_id, rule_id, category, severity, confidence, title, description, recommendation, evidence_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      for (const f of report.findings) {
        insFinding.run(f.id, report.scan_id, pageId, f.rule_id, f.category, f.severity, f.confidence, f.title, f.explanation, f.recommendation, JSON.stringify(f.evidence));
      }
      const insHop = db.prepare('INSERT INTO redirect_hops (scan_id, source_url, destination_url, status_code, hop_number) VALUES (?, ?, ?, ?, ?)');
      for (const h of report.redirect_chain) insHop.run(report.scan_id, h.url, h.location ?? null, h.status, h.hop);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  get(scanId: string): ScanReport | undefined {
    const row = this.db.prepare('SELECT report_json FROM scans WHERE id = ?').get(scanId) as { report_json: string } | undefined;
    return row ? (JSON.parse(row.report_json) as ScanReport) : undefined;
  }

  list(limit = 20, domain?: string): ScanListItem[] {
    const sql = `SELECT id AS scan_id, tool, target_url, domain, started_at, scan_status, overall_risk FROM scans
                 ${domain ? 'WHERE domain = ?' : ''} ORDER BY started_at DESC LIMIT ?`;
    const stmt = this.db.prepare(sql);
    return (domain ? stmt.all(domain, limit) : stmt.all(limit)) as unknown as ScanListItem[];
  }

  /** Deletes scans older than the retention window. Returns the number of scans removed. */
  purgeOlderThan(days: number): number {
    if (days <= 0) return 0;
    const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
    const res = this.db.prepare('DELETE FROM scans WHERE started_at < ?').run(cutoff);
    return Number(res.changes);
  }
}
