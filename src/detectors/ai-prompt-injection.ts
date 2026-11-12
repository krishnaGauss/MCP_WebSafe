import {
  AI_LINK_RE,
  assessInstructions,
  extractAiPrefill,
  findEndorsementClaims,
  type InstructionAssessment,
} from '../analysis/ai-patterns.js';
import { resolveUrl } from '../analysis/url-utils.js';
import { excerptAround, makeFinding, raiseSeverity } from '../risk/evidence.js';
import type { Detector } from '../types/detector.js';
import type { DraftFinding, Evidence, EvidenceSource, Severity } from '../types/finding.js';

const MAX_FINDINGS_PER_CHANNEL = 10;

function describe(a: InstructionAssessment): string {
  return a.families.join(', ');
}

function matchExcerpt(text: string, a: InstructionAssessment): string {
  const first = a.matches[0];
  return first ? excerptAround(text, first.index, first.match.length) : text;
}

function severityFor(a: InstructionAssessment, base: Severity): Severity {
  return a.families.includes('persistence') || a.families.includes('exfiltration') ? raiseSeverity(base) : base;
}

/** Flattens JSON-LD into (path, string) pairs. */
function flattenStrings(value: unknown, path = '$', out: Array<{ path: string; text: string }> = []): Array<{ path: string; text: string }> {
  if (typeof value === 'string') out.push({ path, text: value });
  else if (Array.isArray(value)) value.forEach((v, i) => flattenStrings(v, `${path}[${i}]`, out));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) flattenStrings(v, `${path}.${k}`, out);
  return out;
}

/** Splits text into sentence-ish chunks so each visible finding has a focused excerpt. */
function chunks(text: string): string[] {
  return text.split(/(?<=[.!?])\s+(?=[A-Z"'([])/).reduce<string[]>((acc, s) => {
    const last = acc[acc.length - 1];
    if (last !== undefined && last.length < 120) acc[acc.length - 1] = `${last} ${s}`;
    else acc.push(s);
    return acc;
  }, []);
}

export const aiPromptInjectionDetector: Detector = {
  name: 'ai-prompt-injection',
  run(ctx) {
    const page = ctx.page;
    if (!page) return [];
    const findings: DraftFinding[] = [];

    // AI-001 hidden instructions
    for (const el of page.hidden_elements.slice(0, 500)) {
      const a = assessInstructions(el.text);
      if (!a.flagged) continue;
      findings.push(
        makeFinding('AI-001', {
          severity: severityFor(a, 'high'),
          confidence: a.confidence,
          explanation: `Hidden element (${el.reasons.join('; ') || 'hidden via ancestor'}) contains text matching AI-instruction pattern families: ${describe(a)}.${el.legitimate ? ` The element matches a legitimate hiding pattern (${el.legitimate}), but screen-reader text is still read by AI systems.` : ''}`,
          observed_behaviour: 'Instructions aimed at AI assistants are present in content visitors cannot see.',
          evidence: [{ location: el.selector, source: 'html', visibility: `hidden: ${el.reasons.join('; ') || 'ancestor hidden'}`, excerpt: matchExcerpt(el.text, a), details: { matched_phrases: a.matches.map((m) => m.match).slice(0, 5) } }],
        }),
      );
    }

    // AI-002 comments, attributes, metadata, JSON-LD
    const channels: Array<{ source: EvidenceSource; location: string; text: string; hidden?: boolean }> = [
      ...page.comments.map((c) => ({ source: 'comment' as const, location: c.location, text: c.text })),
      ...page.attributes.map((at) => ({ source: 'attribute' as const, location: `${at.selector} [${at.attribute}]`, text: at.value, hidden: at.hidden })),
      ...page.meta.map((m) => ({ source: 'meta' as const, location: `${m.selector} (${m.key})`, text: m.content })),
      ...page.json_ld.flatMap((j) =>
        j.parsed !== undefined
          ? flattenStrings(j.parsed).map((s) => ({ source: 'json_ld' as const, location: `${j.selector} ${s.path}`, text: s.text }))
          : [{ source: 'json_ld' as const, location: j.selector, text: j.raw }],
      ),
    ];
    let channelCount = 0;
    for (const ch of channels) {
      const a = assessInstructions(ch.text);
      if (!a.flagged) continue;
      if (++channelCount > MAX_FINDINGS_PER_CHANNEL * 3) break;
      findings.push(
        makeFinding('AI-002', {
          severity: severityFor(a, a.strong ? 'high' : 'medium'),
          confidence: a.confidence,
          explanation: `Machine-readable ${ch.source.replace('_', '-')} content matches AI-instruction pattern families: ${describe(a)}.`,
          observed_behaviour: 'Instructions aimed at AI assistants are embedded in markup that humans rarely review.',
          evidence: [{ location: ch.location, source: ch.source, ...(ch.hidden ? { visibility: 'hidden element' } : {}), excerpt: matchExcerpt(ch.text, a), details: { matched_phrases: a.matches.map((m) => m.match).slice(0, 5) } }],
        }),
      );
    }

    // AI-003 visible content
    const topical = /\bprompt[- ]injection\b|\bjailbreak/i.test(page.visible_text);
    const visibleEvidence: Evidence[] = [];
    const visibleFamilies = new Set<string>();
    let visibleStrong = false;
    for (const chunk of chunks(page.visible_text)) {
      const a = assessInstructions(chunk);
      // Visible copy needs corroboration: a strong family plus a second family (e.g. it addresses an AI), or three families.
      if (!a.flagged || !((a.strong && a.families.length >= 2) || a.families.length >= 3)) continue;
      a.families.forEach((f) => visibleFamilies.add(f));
      visibleStrong ||= a.strong;
      visibleEvidence.push({ location: 'visible page text', source: 'text', visibility: 'visible', excerpt: matchExcerpt(chunk, a), details: { families: a.families } });
      if (visibleEvidence.length >= 5) break;
    }
    if (visibleEvidence.length) {
      findings.push(
        makeFinding('AI-003', {
          severity: topical ? 'low' : visibleStrong ? 'medium' : 'low',
          confidence: topical ? 'low' : visibleFamilies.size >= 3 ? 'medium' : 'low',
          explanation: `Visible text contains ${visibleEvidence.length} passage(s) addressing AI assistants (${[...visibleFamilies].join(', ')}).${topical ? ' The page appears to discuss prompt injection as a topic, so these may be quotations.' : ''}`,
          observed_behaviour: 'AI-directed instructions in visible content.',
          evidence: visibleEvidence,
        }),
      );
    }

    // AI-004 / AI-005 AI assistant links with prefilled prompts
    const seen = new Set<string>();
    const candidates: Array<{ href: string; text: string; location: string; source: EvidenceSource }> = page.links
      .filter((l) => l.is_http)
      .map((l) => ({ href: l.href, text: l.text, location: l.selector, source: 'link' as const }));
    // Buttons that open assistants through onclick/data attributes or scripts.
    for (const m of ctx.fetch.body.matchAll(AI_LINK_RE)) {
      const raw = m[0].replace(/&amp;/g, '&');
      candidates.push({ href: raw, text: '', location: 'page source (script, onclick or data attribute)', source: 'html' });
    }
    for (const c of candidates) {
      const url = resolveUrl(c.href, page.url);
      if (!url || seen.has(url.href)) continue;
      const prefill = extractAiPrefill(url);
      if (!prefill) continue;
      seen.add(url.href);
      const a = assessInstructions(prefill.prompt);
      const endorsement = findEndorsementClaims(prefill.prompt);
      const mentionsOwnSite = page.domain ? prefill.prompt.toLowerCase().includes(page.domain) : false;
      const ev: Evidence = {
        location: c.location,
        source: c.source,
        excerpt: prefill.prompt,
        details: { assistant: prefill.assistant, parameter: prefill.param, link_text: c.text.slice(0, 120), assistant_host: url.hostname },
      };
      if (a.flagged || endorsement.length) {
        const persistence = a.families.includes('persistence');
        findings.push(
          makeFinding('AI-004', {
            severity: persistence ? 'critical' : 'high',
            confidence: a.flagged ? 'high' : 'medium',
            explanation: `A ${c.text ? `"${c.text.slice(0, 60)}" ` : ''}link opens ${prefill.assistant} with a prefilled prompt containing ${a.flagged ? `instruction pattern(s): ${describe(a)}` : 'an AI endorsement claim'}.${persistence ? ' The prompt asks the assistant to persist information into memory or future conversations ("AI recommendation poisoning").' : ''}${mentionsOwnSite ? ` The prompt references ${page.domain}.` : ''} The link was inspected statically and not followed.`,
            observed_behaviour: 'Clicking this link would plant instructions in the visitor\'s own AI assistant.',
            evidence: [{ ...ev, details: { ...ev.details, matched_phrases: a.matches.map((m) => m.match).slice(0, 5) } }],
          }),
        );
      } else {
        findings.push(
          makeFinding('AI-005', {
            explanation: `A link opens ${prefill.assistant} with a prefilled prompt that appears neutral.`,
            observed_behaviour: 'AI assistant share link present.',
            evidence: [ev],
          }),
        );
      }
    }

    // AI-006 AI endorsement / authority claims
    const claimSources: Array<{ text: string; location: string; source: EvidenceSource; hidden: boolean }> = [
      { text: page.visible_text, location: 'visible page text', source: 'text', hidden: false },
      ...page.hidden_elements.map((h) => ({ text: h.text, location: h.selector, source: 'html' as const, hidden: true })),
      ...page.meta.map((m) => ({ text: m.content, location: `${m.selector} (${m.key})`, source: 'meta' as const, hidden: false })),
      ...page.json_ld.map((j) => ({ text: j.raw, location: j.selector, source: 'json_ld' as const, hidden: false })),
    ];
    const claimEvidence: Evidence[] = [];
    let claimHidden = false;
    for (const src of claimSources) {
      for (const claim of findEndorsementClaims(src.text)) {
        claimHidden ||= src.hidden || src.source === 'json_ld';
        claimEvidence.push({ location: src.location, source: src.source, ...(src.hidden ? { visibility: 'hidden' } : {}), excerpt: excerptAround(src.text, claim.index, claim.match.length, 200) });
      }
    }
    if (claimEvidence.length) {
      findings.push(
        makeFinding('AI-006', {
          severity: claimHidden ? 'medium' : 'low',
          explanation: `${claimEvidence.length} claim(s) of endorsement or ranking by AI assistants/AI companies were found. These cannot be verified from the page and may be repeated by AI systems summarising it.`,
          observed_behaviour: 'Unverifiable AI authority claims.',
          evidence: claimEvidence,
        }),
      );
    }

    return findings;
  },
};
