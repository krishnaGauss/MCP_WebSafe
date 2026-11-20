import { assessInstructions } from '../analysis/ai-patterns.js';
import { matchSpamKeywords } from '../analysis/keywords.js';
import { foldForMatching } from '../analysis/text-normalizer.js';
import { isCrossSite, registrableDomain } from '../analysis/url-utils.js';
import { WEAK_COLOUR_REASON } from '../analysis/visibility.js';
import { makeFinding } from '../risk/evidence.js';
import type { Detector } from '../types/detector.js';
import type { Confidence, DraftFinding, Severity } from '../types/finding.js';

const MIN_HIDDEN_TEXT = 40;

function ruleForReasons(reasons: string[]): { rule: string; confidence: Confidence } {
  const joined = reasons.join(' ');
  if (/off-screen/.test(joined)) return { rule: 'HID-003', confidence: 'medium' };
  if (/colour matches/.test(joined)) return { rule: 'HID-004', confidence: joined.includes(WEAK_COLOUR_REASON) ? 'low' : 'medium' };
  if (/font-size|zero-size|transform/.test(joined)) return { rule: 'HID-005', confidence: 'medium' };
  if (/clip/.test(joined)) return { rule: 'HID-001', confidence: 'medium' };
  return { rule: 'HID-001', confidence: 'low' };
}

/**
 * display:none, visibility:hidden, opacity:0 and the hidden attribute are how JavaScript UIs show and hide
 * state (alerts, fade-in animations, panels). On their own they say little about intent.
 */
const TOGGLE_REASON = /^(display:none|visibility:|opacity:|hidden attribute)/;

export const hiddenContentDetector: Detector = {
  name: 'hidden-content',
  run(ctx) {
    const page = ctx.page;
    if (!page) return [];
    const findings: DraftFinding[] = [];

    for (const el of page.hidden_elements) {
      const reasonText = el.reasons.length ? el.reasons.join('; ') : 'hidden';
      // Hidden AI instructions are reported by the AI detector (AI-001); avoid duplicates.
      // Obfuscated variants are reported by the obfuscation detector (AI-008).
      const folded = foldForMatching(el.text).folded;
      if (assessInstructions(el.text).flagged || assessInstructions(folded).flagged) continue;

      const externalLinks = el.links.filter((href) => /^https?:/i.test(href) && isCrossSite(href, page.url));
      // Match on the de-obfuscated text too, so look-alike spelling (e.g. Cyrillic letters in "casino") is caught.
      const spam = matchSpamKeywords(`${folded} ${externalLinks.join(' ')}`);
      const suspicious = spam.length > 0;
      // Colour matching against an undeclared (default) background is weak: the text may sit on an image
      // or on a background from an external stylesheet. Only report it when the content is itself suspicious.
      const weakOnly = el.reasons.length > 0 && el.reasons.every((r) => r.startsWith(WEAK_COLOUR_REASON));
      if (weakOnly && !suspicious) continue;

      if (externalLinks.length > 0) {
        if (el.legitimate && !suspicious) continue; // e.g. social links inside a collapsed menu
        const domains = [...new Set(externalLinks.map((h) => registrableDomain(h)).filter(Boolean))];
        const severity: Severity = suspicious ? 'critical' : 'high';
        findings.push(
          makeFinding('HID-002', {
            severity,
            confidence: suspicious || !el.legitimate ? (el.reasons.length ? 'high' : 'medium') : 'low',
            explanation: `${externalLinks.length} link(s) to ${domains.join(', ')} are inside a hidden element (${reasonText}).${suspicious ? ` Keywords matched: ${spam.flatMap((s) => s.terms).join(', ')}.` : ''}${el.legitimate ? ` Note: element matches a legitimate UI pattern (${el.legitimate}).` : ''}`,
            observed_behaviour: 'External links present in the HTML but not visible to visitors.',
            evidence: [
              {
                location: el.selector,
                source: 'html',
                visibility: `hidden: ${reasonText}`,
                excerpt: el.text,
                details: { links: externalLinks.slice(0, 10) },
              },
            ],
          }),
        );
        continue;
      }

      if (el.text.length < MIN_HIDDEN_TEXT) continue;
      if (el.legitimate && !suspicious) continue;
      const { rule, confidence } = ruleForReasons(el.reasons);
      const toggleOnly = el.reasons.every((r) => TOGGLE_REASON.test(r));
      // Ordinary text hidden by a UI toggle is recorded for review but does not raise the risk level.
      if (toggleOnly && !suspicious && el.text.length < 200) continue;
      findings.push(
        makeFinding(rule, {
          severity: suspicious ? 'high' : toggleOnly ? 'informational' : undefined,
          confidence: suspicious ? 'high' : el.legitimate ? 'low' : confidence,
          explanation: `${el.text.length} characters of text are hidden (${reasonText}).${suspicious ? ` Keywords matched: ${spam.flatMap((s) => s.terms).join(', ')}.` : ''}${el.legitimate ? ` Element matches a legitimate UI pattern (${el.legitimate}) but contains suspicious keywords.` : ''}`,
          observed_behaviour: 'Text present in the HTML but not visible to visitors.',
          evidence: [{ location: el.selector, source: 'html', visibility: `hidden: ${reasonText}`, excerpt: el.text }],
        }),
      );
    }

    // Visible-but-tiny external links.
    const tiny = page.links.filter((l) => l.tiny && !l.hidden && l.external);
    if (tiny.length) {
      const spam = tiny.some((l) => matchSpamKeywords(`${foldForMatching(l.text).folded} ${l.href}`).length);
      findings.push(
        makeFinding('HID-005', {
          severity: spam ? 'high' : 'medium',
          explanation: `${tiny.length} external link(s) are rendered with unreadably small text.`,
          observed_behaviour: 'Links technically visible but too small for a visitor to notice.',
          evidence: tiny.map((l) => ({ location: l.selector, source: 'link' as const, visibility: 'tiny text (≤3px)', excerpt: l.text, details: { href: l.href } })),
        }),
      );
    }
    return findings;
  },
};
