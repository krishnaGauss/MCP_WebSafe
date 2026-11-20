import { getRule } from '../rules/catalog.js';
import type { Confidence, DraftFinding, Evidence, Severity } from '../types/finding.js';

const MAX_EXCERPT = 300;

/**
 * Characters that render as nothing or change rendering order: C0/C1 controls, every Unicode format
 * character (zero-width, bidi controls, Unicode tag characters used for "ASCII smuggling", soft hyphen),
 * variation selectors and private-use code points. Scanned text passed to an AI agent must never contain
 * these, or a page could smuggle instructions through GEO Shield's own output.
 */
// \p{Cs} also removes lone surrogates left when an excerpt is cut next to an astral-plane character.
const INVISIBLE_RE = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/gu;

/** Removes invisible characters while keeping line breaks and tabs. */
export function stripInvisible(text: string): string {
  return text.replace(/[\t\n\r]/g, ' ').replace(INVISIBLE_RE, '');
}

/** Applies {@link stripInvisible} to every string in a JSON-like value (reports and tool results). */
export function deepStripInvisible<T>(value: T): T {
  if (typeof value === 'string') return stripInvisible(value) as T;
  if (Array.isArray(value)) return value.map((v) => deepStripInvisible(v)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = deepStripInvisible(v);
    return out as T;
  }
  return value;
}

/**
 * Prepare scanned content for inclusion in a report. The result is still UNTRUSTED data:
 * this only strips invisible characters (which can hide text from human reviewers and smuggle
 * instructions to models), collapses whitespace and truncates.
 */
export function sanitizeExcerpt(text: string, max = MAX_EXCERPT): string {
  const cleaned = text.replace(/\s+/g, ' ').replace(INVISIBLE_RE, '').trim();
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
