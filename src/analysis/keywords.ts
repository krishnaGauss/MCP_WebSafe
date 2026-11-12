/** High-risk commercial keyword lists used by spam/injection rules. */
export type SpamCategory = 'gambling' | 'pharma' | 'adult' | 'scam_finance' | 'counterfeit';

const LISTS: Record<SpamCategory, RegExp[]> = {
  gambling: [
    /\bcasinos?\b/i, /\bslots?\s*(online|gacor|machines?|games?)\b/i, /\bslot\s?gacor\b/i, /\bsitus\s+(slot|judi|togel)\b/i, /\bjudi\b/i,
    /\btogel\b/i, /\bpoker\b/i, /\broulette\b/i, /\bblackjack\b/i, /\bsportsbook\b/i, /\bbetting\b/i, /\bbookmakers?\b/i,
    /\bjackpot\b/i, /\bfree\s+spins?\b/i, /\bno[- ]deposit\s+bonus\b/i, /\bbaccarat\b/i, /\bgambling\b/i, /\bbet\s?\d{2,3}\b/i,
  ],
  pharma: [
    /\bviagra\b/i, /\bcialis\b/i, /\blevitra\b/i, /\btramadol\b/i, /\bxanax\b/i, /\boxycodone\b/i, /\bambien\b/i, /\bphentermine\b/i,
    /\bwithout\s+(a\s+)?prescription\b/i, /\bno\s+prescription\b/i, /\bonline\s+pharmacy\b/i, /\bbuy\s+(cheap\s+)?(pills|meds|generic)\b/i,
  ],
  adult: [/\bporn\w*\b/i, /\bxxx\b/i, /\bescorts?\b/i, /\bcam\s?girls?\b/i, /\bnude\s+(pics|photos|videos)\b/i, /\bhookups?\b/i, /\bonlyfans\s+leaks?\b/i],
  scam_finance: [
    /\bpayday\s+loans?\b/i, /\bcrypto\s+(doubler|giveaway)\b/i, /\bguaranteed\s+(profits?|returns?)\b/i, /\bbinary\s+options\b/i,
    /\bget\s+rich\s+quick\b/i, /\bfree\s+(bitcoin|btc|crypto)\b/i, /\bloan\s+approval\s+guaranteed\b/i,
  ],
  counterfeit: [/\breplica\s+(watches|handbags|bags|rolex)\b/i, /\bfake\s+(ids?|passports?|diplomas?)\b/i, /\bcheap\s+(ugg|ray[- ]?ban|oakley|louis\s+vuitton)\b/i],
};

export interface SpamMatch {
  category: SpamCategory;
  terms: string[];
}

export function matchSpamKeywords(text: string): SpamMatch[] {
  if (!text) return [];
  const out: SpamMatch[] = [];
  for (const [category, patterns] of Object.entries(LISTS) as Array<[SpamCategory, RegExp[]]>) {
    const terms = new Set<string>();
    for (const re of patterns) {
      const m = re.exec(text);
      if (m) terms.add(m[0].toLowerCase());
    }
    if (terms.size) out.push({ category, terms: [...terms] });
  }
  return out;
}

/** Counts total keyword occurrences per category — used to judge whether a page is *about* the topic. */
export function spamTopicCounts(text: string): Record<SpamCategory, number> {
  const counts = { gambling: 0, pharma: 0, adult: 0, scam_finance: 0, counterfeit: 0 } as Record<SpamCategory, number>;
  for (const [category, patterns] of Object.entries(LISTS) as Array<[SpamCategory, RegExp[]]>) {
    for (const re of patterns) {
      const g = new RegExp(re.source, 'gi');
      counts[category] += (text.match(g) ?? []).length;
    }
  }
  return counts;
}

export const TOPIC_THRESHOLD = 5;
