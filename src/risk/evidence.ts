import { getRule } from '../rules/catalog.js';
import type { Confidence, DraftFinding, Evidence, Severity } from '../types/finding.js';

const MAX_EXCERPT = 300;

/**
 * Prepare scanned content for inclusion in a report. The result is still UNTRUSTED data:
 * this only strips control/bidi characters (which can hide text from human reviewers),
 * collapses whitespace and truncates.
 */
export function sanitizeExcerpt(text: string, max = MAX_EXCERPT): string {
  const cleaned = text
    // C0/C1 controls, zero-width and bidi override characters.
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

/** Excerpt centred on a match within a longer text. */
export function excerptAround(text: string, index: number, matchLength: number, max = MAX_EXCERPT): string {
  if (text.length <= max) return sanitizeExcerpt(text, max);
  const pad = Math.max(0, Math.floor((max - matchLength) / 2));
  const start = Math.max(0, index - pad);
  const slice = text.slice(start, start + max);
  return sanitizeExcerpt(`${start > 0 ? '…' : ''}${slice}`, max);
}

export function evidence(e: Evidence): Evidence {
  return e.excerpt !== undefined ? { ...e, excerpt: sanitizeExcerpt(e.excerpt) } : e;
}

export interface FindingInput {
  explanation: string;
  observed_behaviour: string;
  evidence: Evidence[];
  severity?: Severity;
  confidence?: Confidence;
  title?: string;
}

/** Builds a draft finding from a rule definition plus observation-specific details. */
export function makeFinding(ruleId: string, input: FindingInput): DraftFinding {
  const rule = getRule(ruleId);
  return {
    rule_id: rule.rule_id,
    category: rule.category,
    title: input.title ?? rule.title,
    severity: input.severity ?? rule.default_severity,
    confidence: input.confidence ?? rule.default_confidence,
    explanation: input.explanation,
    observed_behaviour: input.observed_behaviour,
    evidence: input.evidence.slice(0, 15).map(evidence),
    potential_impact: rule.potential_impact,
    recommendation: rule.recommendation,
    false_positive_considerations: rule.false_positive_considerations,
  };
}

export const SEVERITY_ORDER: Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];
export const raiseSeverity = (s: Severity): Severity => SEVERITY_ORDER[Math.min(SEVERITY_ORDER.indexOf(s) + 1, 4)]!;
export const lowerSeverity = (s: Severity): Severity => SEVERITY_ORDER[Math.max(SEVERITY_ORDER.indexOf(s) - 1, 0)]!;
