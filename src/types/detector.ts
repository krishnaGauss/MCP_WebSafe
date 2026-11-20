import type { PageSnapshot } from '../analysis/html-parser.js';
import type { DraftFinding } from './finding.js';
import type { DeclaredRedirect, FetchResult } from './scan.js';

export interface DetectorContext {
  fetch: FetchResult;
  /** Present only when the final response was HTML. */
  page?: PageSnapshot;
  declaredRedirects: DeclaredRedirect[];
  /** Scan-level notices a detector can add (e.g. analysis limits reached). */
  notes?: string[];
}

export interface Detector {
  name: string;
  run(ctx: DetectorContext): DraftFinding[];
}
