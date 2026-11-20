import type { InstructionAssessment } from '../analysis/ai-patterns.js';
import { collectTextChannels, type TextChannel } from '../analysis/channels.js';
import { assessText } from '../analysis/deobfuscate.js';
import type { SpamMatch } from '../analysis/keywords.js';
import { newDecodeBudget } from '../analysis/payload-decoder.js';
import { describeCodepoints, findBidiOverrides } from '../analysis/unicode-smuggling.js';
import { excerptAround, makeFinding, sanitizeExcerpt } from '../risk/evidence.js';
import type { Detector } from '../types/detector.js';
import type { Confidence, DraftFinding, Evidence, Severity } from '../types/finding.js';

const MAX_PER_RULE = 20;

const PAYLOAD_LABEL = {
  tag_characters: 'Unicode tag characters',
  variation_selectors: 'variation selectors',
  zero_width_binary: 'zero-width characters used as binary',
} as const;

function contentSeverity(a: InstructionAssessment, spam: SpamMatch[]): Severity | undefined {
  if (a.flagged && (a.families.includes('persistence') || a.families.includes('exfiltration'))) return 'critical';
  if (a.flagged || spam.length) return 'high';
  return undefined;
}

function whatItSays(a: InstructionAssessment, spam: SpamMatch[]): string {
  if (a.flagged) return `AI-instruction pattern families: ${a.families.join(', ')}`;
  if (spam.length) return `${spam.map((s) => s.category).join(', ')} keywords (${spam.flatMap((s) => s.terms).slice(0, 5).join(', ')})`;
  return 'readable text';
}

function channelVisibility(ch: TextChannel): string {
  return ch.kind === 'visible' ? 'visible text' : ch.hidden ? `not visible (${ch.kind.replace('_', ' ')})` : ch.kind.replace('_', ' ');
}

export const unicodeObfuscationDetector: Detector = {
  name: 'unicode-obfuscation',
  run(ctx) {
    const page = ctx.page;
    if (!page) return [];
    const findings: Record<'AI-007' | 'AI-008' | 'AI-009', DraftFinding[]> = { 'AI-007': [], 'AI-008': [], 'AI-009': [] };
    const budget = newDecodeBudget();
    const seenDecoded = new Set<string>();

    for (const ch of collectTextChannels(page, ctx.fetch.body)) {
      const t = assessText(ch.text, { decodePayloads: ch.kind !== 'visible', budget });

      // AI-007: text smuggled in invisible characters.
      for (const p of t.hidden) {
        if (findings['AI-007'].length >= MAX_PER_RULE || seenDecoded.has(`${ch.location}|${p.decoded}`)) continue;
        seenDecoded.add(`${ch.location}|${p.decoded}`);
        const sev = contentSeverity(p.instructions, p.spam) ?? (p.kind === 'tag_characters' && p.substantial ? 'medium' : 'low');
        findings['AI-007'].push(
          makeFinding('AI-007', {
            severity: sev,
            confidence: 'high',
            explanation: `${PAYLOAD_LABEL[p.kind]} in ${ch.kind.replace('_', ' ')} content decode to ${p.decoded.length} characters of hidden text containing ${whatItSays(p.instructions, p.spam)}.${sev === 'low' ? ' Short payloads like this are often copy-tracking watermarks.' : ''} The excerpt is the decoded text.`,
            observed_behaviour: 'Text that renders as nothing for people but is read by language models.',
            evidence: [
              {
                location: ch.location,
                source: ch.source,
                visibility: `invisible (${PAYLOAD_LABEL[p.kind]})`,
                excerpt: p.decoded,
                details: {
                  encoding: p.kind,
                  codepoints: describeCodepoints(p.run.codepoints),
                  visible_text_around: excerptAround(ch.text, p.run.start, 0, 160),
                  ...(p.instructions.flagged ? { matched_phrases: p.instructions.matches.map((m) => m.match).slice(0, 5) } : {}),
                },
              },
            ],
          }),
        );
      }

      // AI-008: instructions that only match after de-obfuscation.
      const f = t.folded;
      if (f && !t.raw.flagged && f.instructions.flagged && findings['AI-008'].length < MAX_PER_RULE) {
        const a = f.instructions;
        const persist = a.families.includes('persistence') || a.families.includes('exfiltration');
        const strongEvidence = f.transforms.length >= 2 || a.families.length >= 2;
        const first = a.matches[0];
        const ev: Evidence = {
          location: ch.location,
          source: ch.source,
          visibility: channelVisibility(ch),
          excerpt: first ? excerptAround(f.folded, first.index, first.match.length) : f.folded,
          details: {
            obfuscation: f.transforms,
            original_text: sanitizeExcerpt(ch.text, 200),
            ...(f.homoglyphs.length ? { lookalike_codepoints: describeCodepoints(f.homoglyphs) } : {}),
            matched_phrases: a.matches.map((m) => m.match).slice(0, 5),
          },
        };
        findings['AI-008'].push(
          makeFinding('AI-008', {
            severity: persist ? 'critical' : 'high',
            confidence: strongEvidence ? 'high' : 'medium',
            explanation: `${ch.kind === 'visible' ? 'Visible' : `Non-visible ${ch.kind.replace('_', ' ')}`} text matches AI-instruction pattern families (${a.families.join(', ')}) only after undoing obfuscation: ${f.transforms.join(', ')}. The excerpt shows the de-obfuscated text; original_text shows it as written.`,
            observed_behaviour: 'Instructions disguised so that filters and reviewers miss them while language models still read them.',
            evidence: [ev],
          }),
        );
      }

      // AI-009: encoded payloads that decode to instructions or spam.
      for (const e of t.encoded) {
        const sev = contentSeverity(e.instructions, e.spam);
        if (!sev || findings['AI-009'].length >= MAX_PER_RULE || seenDecoded.has(`${ch.location}|${e.decoded}`)) continue;
        seenDecoded.add(`${ch.location}|${e.decoded}`);
        findings['AI-009'].push(
          makeFinding('AI-009', {
            severity: sev,
            confidence: e.instructions.strong ? 'high' : 'medium',
            explanation: `A ${e.layers.join(' inside ')}-encoded blob in ${ch.kind.replace('_', ' ')} content decodes to text containing ${whatItSays(e.instructions, e.spam)}. The excerpt is the decoded text.`,
            observed_behaviour: 'Encoded content that AI agents and decoding tools can read but reviewers and keyword filters cannot.',
            evidence: [
              {
                location: ch.location,
                source: ch.source,
                visibility: channelVisibility(ch),
                excerpt: e.decoded,
                details: {
                  layers: e.layers,
                  encoded: e.raw,
                  ...(e.fold.transforms.length ? { obfuscation: e.fold.transforms } : {}),
                  ...(e.instructions.flagged ? { matched_phrases: e.instructions.matches.map((m) => m.match).slice(0, 5) } : {}),
                },
              },
            ],
          }),
        );
      }
    }
    return [...findings['AI-007'], ...findings['AI-008'], ...findings['AI-009']];
  },
};

export const bidiOverrideDetector: Detector = {
  name: 'bidi-override',
  run(ctx) {
    const page = ctx.page;
    if (!page) return [];
    const out: DraftFinding[] = [];
    for (const ch of collectTextChannels(page, ctx.fetch.body)) {
      for (const o of findBidiOverrides(ch.text)) {
        if (out.length >= 10) return out;
        const displayed = o.codepoint === 0x202e ? [...o.segment].reverse().join('') : o.segment;
        const t = assessText(`${o.segment} ${displayed}`, { decodePayloads: false });
        const harmful = t.raw.flagged || !!t.folded?.instructions.flagged || t.rawSpam.length > 0 || !!t.folded?.spam.length;
        const confidence: Confidence = harmful ? 'high' : 'medium';
        out.push(
          makeFinding('HID-006', {
            severity: harmful ? 'high' : 'medium',
            confidence,
            explanation: `A ${o.codepoint === 0x202e ? 'RIGHT-TO-LEFT' : 'LEFT-TO-RIGHT'} OVERRIDE character (U+${o.codepoint.toString(16).toUpperCase()}) in ${ch.kind.replace('_', ' ')} content without any right-to-left script changes the order the text is displayed in.${harmful ? ' The affected text contains AI instructions or spam keywords.' : ''}`,
            observed_behaviour: 'Stored text and displayed text differ.',
            evidence: [
              {
                location: ch.location,
                source: ch.source,
                visibility: channelVisibility(ch),
                excerpt: o.segment,
                details: { displayed_as: sanitizeExcerpt(displayed, 160), codepoint: describeCodepoints([o.codepoint]) },
              },
            ],
          }),
        );
      }
    }
    return out;
  },
};
