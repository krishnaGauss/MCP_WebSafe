import { assessCompact, assessInstructions, type InstructionAssessment } from './ai-patterns.js';
import { matchSpamKeywords, type SpamMatch } from './keywords.js';
import { findEncodedPayloads, newDecodeBudget, type DecodeBudget, type DecodedPayload } from './payload-decoder.js';
import { foldForMatching, type FoldResult } from './text-normalizer.js';
import { extractHiddenPayloads, type HiddenPayload } from './unicode-smuggling.js';

export interface DecodedAssessment {
  instructions: InstructionAssessment;
  spam: SpamMatch[];
  /** Folding applied to the decoded text itself (e.g. a base64 payload that also uses homoglyphs). */
  fold: FoldResult;
}

export interface TextAssessment {
  raw: InstructionAssessment;
  rawSpam: SpamMatch[];
  /** Present only when folding changed the text. */
  folded?: FoldResult & { instructions: InstructionAssessment; spam: SpamMatch[] };
  hidden: Array<HiddenPayload & DecodedAssessment>;
  encoded: Array<DecodedPayload & DecodedAssessment>;
}

function assessDecoded(text: string): DecodedAssessment {
  const fold = foldForMatching(text);
  const a = assessInstructions(text);
  const instructions = a.flagged ? a : assessInstructions(fold.folded);
  const spam = matchSpamKeywords(text).length ? matchSpamKeywords(text) : matchSpamKeywords(fold.folded);
  return { instructions, spam, fold };
}

/**
 * Runs the instruction and spam patterns on a text as written, on its de-obfuscated form,
 * on any text smuggled in invisible characters, and on any encoded payloads it contains.
 */
export function assessText(text: string, opts: { decodePayloads?: boolean; budget?: DecodeBudget } = {}): TextAssessment {
  const raw = assessInstructions(text);
  const rawSpam = matchSpamKeywords(text);
  const fold = foldForMatching(text);
  const result: TextAssessment = { raw, rawSpam, hidden: [], encoded: [] };
  if (fold.transforms.length) {
    let instructions = assessInstructions(fold.folded);
    // Joined spaced letters lose word boundaries; fall back to boundary-free patterns.
    if (!instructions.flagged && fold.transforms.includes('spaced_letters')) instructions = assessCompact(fold.folded);
    result.folded = { ...fold, instructions, spam: matchSpamKeywords(fold.folded) };
  }
  for (const p of extractHiddenPayloads(text)) result.hidden.push({ ...p, ...assessDecoded(p.decoded) });
  if (opts.decodePayloads !== false) {
    for (const p of findEncodedPayloads(text, opts.budget ?? newDecodeBudget())) result.encoded.push({ ...p, ...assessDecoded(p.decoded) });
  }
  return result;
}

/** True when the text carries AI instructions in any form (raw, de-obfuscated, smuggled or encoded). */
export function anyInstructions(t: TextAssessment): boolean {
  return t.raw.flagged || !!t.folded?.instructions.flagged || t.hidden.some((h) => h.instructions.flagged) || t.encoded.some((e) => e.instructions.flagged);
}
