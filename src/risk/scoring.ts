import { CATEGORIES, SEVERITIES, type Category, type Confidence, type Finding, type Severity } from '../types/finding.js';
import type { RiskSummary } from '../types/scan.js';
import { lowerSeverity, SEVERITY_ORDER } from './evidence.js';

const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 40, high: 20, medium: 8, low: 3, informational: 0 };
const CONFIDENCE_WEIGHT: Record<Confidence, number> = { high: 1, medium: 0.7, low: 0.4 };

/**
 * Severity and confidence are kept separate on each finding. The overall risk is the highest
 * severity backed by at least medium confidence; low-confidence-only signals are stepped down one level.
 */
export function summarizeRisk(findings: Finding[]): RiskSummary {
  const by_severity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  const by_category: Partial<Record<Category, number>> = {};
  let score = 0;
  let overall: Severity | 'none' = 'none';
  const rank = (s: Severity | 'none'): number => (s === 'none' ? -1 : SEVERITY_ORDER.indexOf(s));

  for (const f of findings) {
    by_severity[f.severity]++;
    by_category[f.category] = (by_category[f.category] ?? 0) + 1;
    score += SEVERITY_WEIGHT[f.severity] * CONFIDENCE_WEIGHT[f.confidence];
    const effective = f.confidence === 'low' ? lowerSeverity(f.severity) : f.severity;
    if (effective !== 'informational' && rank(effective) > rank(overall)) overall = effective;
  }
  for (const c of CATEGORIES) if (by_category[c] === 0) delete by_category[c];

  const actionable = findings.filter((f) => f.severity !== 'informational').length;
  const headline =
    overall === 'none'
      ? actionable === 0
        ? 'No suspicious indicators were detected by the implemented rules.'
        : 'Only weak indicators were detected.'
      : `${actionable} indicator(s) found; highest effective risk is ${overall.toUpperCase()}.`;

  return { overall_risk: overall, score: Math.min(100, Math.round(score)), total_findings: findings.length, by_severity, by_category, headline };
}

/** Sort most severe first, then by confidence. */
export function sortFindings(findings: Finding[]): Finding[] {
  const conf: Confidence[] = ['low', 'medium', 'high'];
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) || conf.indexOf(b.confidence) - conf.indexOf(a.confidence),
  );
}
