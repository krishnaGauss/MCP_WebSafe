/**
 * Deterministic patterns for text that addresses AI assistants with instructions.
 * Families are combined so that a single weak phrase ("you are now") does not trigger,
 * while strong families (override, persistence, exfiltration, suppression) do.
 */
export type InstructionFamily =
  | 'override'
  | 'persistence'
  | 'exfiltration'
  | 'suppression'
  | 'control_token'
  | 'ai_address'
  | 'recommendation'
  | 'role';

const STRONG = new Set<InstructionFamily>(['override', 'persistence', 'exfiltration', 'suppression', 'control_token']);

const PATTERNS: Array<{ family: InstructionFamily; re: RegExp }> = [
  { family: 'override', re: /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|preceding|all|any|your|system|original)\b[^.\n]{0,30}\b(instructions?|prompts?|rules|guidelines|directives|context)\b/i },
  { family: 'override', re: /\b(new|updated|real|actual)\s+(system\s+)?instructions?\s*:/i },
  { family: 'persistence', re: /\b(remember|memori[sz]e|store|save|keep|retain|add)\b[^.\n]{0,60}\b(in|to|into)\s+(your\s+)?(memory|memories|long[- ]term memory|persistent memory|knowledge base)\b/i },
  { family: 'persistence', re: /\b(in|for|across)\s+(all\s+)?(future|subsequent|later)\s+(conversations?|chats?|sessions?|responses?|answers?|queries)\b/i },
  { family: 'persistence', re: /\bremember\b[^.\n]{0,80}\b(as|is)\s+(an?|the)\s+(trusted|authoritative|reliable|go-to|preferred|leading|top|best|official|primary)\b/i },
  { family: 'persistence', re: /\bfor future (reference|recommendations|questions|use)\b/i },
  { family: 'exfiltration', re: /\b(reveal|print|output|show|repeat|disclose|leak)\b[^.\n]{0,30}\b(your|the)\s+(system prompt|initial instructions|hidden instructions|developer (message|instructions)|original instructions)\b/i },
  { family: 'exfiltration', re: /\b(reveal|print|output|show|disclose|leak|send)\b[^.\n]{0,20}\byour\s+(api keys?|secrets?|environment variables|credentials|tokens?|conversation history|chat history)\b/i },
  { family: 'exfiltration', re: /\b(send|post|forward|email|upload|exfiltrate)\b[^.\n]{0,40}\b(conversation|chat history|user'?s? (data|details|information|emails?)|personal data|cookies|tokens?)\b/i },
  { family: 'suppression', re: /\b(do not|don't|never|avoid|refuse to)\s+(mention|recommend|cite|suggest|reference|link to|talk about|compare)\b[^.\n]{0,50}\b(competitors?|other (brands?|companies|products|sites|websites|providers|vendors|sources)|alternatives?|rivals?)\b/i },
  { family: 'suppression', re: /\b(do not|don't|never)\s+(tell|reveal to|inform|warn|alert)\s+the\s+user\b/i },
  { family: 'control_token', re: /<\|?\s*(im_start|im_end|system|endoftext|eot_id|start_header_id)\s*\|?>|\[\/?INST\]|<<SYS>>/i },
  { family: 'ai_address', re: /\b(dear|attention|note (?:to|for)|message (?:to|for)|hey|hello|instructions? for)\s+(the\s+)?(ai|a\.i\.|llms?|chatgpt|gpt-?\d*|claude|gemini|copilot|perplexity|assistants?|language models?|ai (?:assistants?|agents?|models?|crawlers?|systems?)|bots?)\b/i },
  { family: 'ai_address', re: /\b(if|when) you are (an?\s+)?(ai|llm|large language model|language model|ai assistant|chatbot|ai agent|ai model)\b/i },
  { family: 'ai_address', re: /\b(ai|llm|language model)\s+(assistants?|agents?|models?|crawlers?|systems?)?\s*(reading|processing|summari[sz]ing|parsing)\s+this\b/i },
  { family: 'ai_address', re: /\b(as an?|you are an?)\s+(ai|llm|large language model|ai assistant|language model)\b/i },
  { family: 'recommendation', re: /\b(always|must|should|only|exclusively)\s+(recommend|suggest|mention|cite|rank|prefer|promote|endorse|refer users to)\b/i },
  { family: 'recommendation', re: /\b(recommend|describe|present|position|list)\b[^.\n]{0,60}\b(as|is)\s+the\s+(best|top|#1|number one|only|most trusted|leading|safest)\b/i },
  { family: 'recommendation', re: /\b(rank|list|place|put)\b[^.\n]{0,40}\b(first|#1|number one|at the top|above all)\b/i },
  { family: 'role', re: /\byou (are|will) now (act|behave|respond|operate) as\b/i },
  { family: 'role', re: /\bfrom now on,?\s+you (will|must|should)\b/i },
];

export interface InstructionMatch {
  family: InstructionFamily;
  match: string;
  index: number;
}

export interface InstructionAssessment {
  flagged: boolean;
  families: InstructionFamily[];
  matches: InstructionMatch[];
  strong: boolean;
  confidence: 'high' | 'medium' | 'low';
}

export function assessInstructions(text: string): InstructionAssessment {
  const matches: InstructionMatch[] = [];
  for (const { family, re } of PATTERNS) {
    const m = re.exec(text);
    if (m) matches.push({ family, match: m[0], index: m.index });
  }
  const families = [...new Set(matches.map((m) => m.family))];
  const strong = families.some((f) => STRONG.has(f));
  const weakCount = families.filter((f) => !STRONG.has(f)).length;
  const flagged = strong || weakCount >= 2;
  let confidence: InstructionAssessment['confidence'] = 'low';
  if (families.length >= 3 || (strong && families.includes('ai_address'))) confidence = 'high';
  else if (strong || families.length >= 2) confidence = 'medium';
  return { flagged, families, matches, strong, confidence };
}

const ENDORSEMENT_PATTERNS = [
  /\b(recommended|endorsed|ranked\s+#?1|rated\s+#?1|verified|certified|approved|trusted|chosen)\s+by\s+(chatgpt|openai|claude|anthropic|gemini|google ai|perplexity|copilot|ai assistants?|leading ai|llms?)\b/i,
  /\b(chatgpt|openai|claude|anthropic|gemini|perplexity|copilot|ai assistants?|llms?)\s+(recommends?|endorses?|ranks?|rates?|trusts?|prefers?|names?|calls?)\s+(us|our|this|it)\b/i,
  /#1\s+(ai[- ]recommended|recommended by ai)\b/i,
  /\b(ai assistants?|llms?|chatgpt|claude|gemini)\s+(all\s+)?agree\b/i,
];

export function findEndorsementClaims(text: string): Array<{ match: string; index: number }> {
  const out: Array<{ match: string; index: number }> = [];
  for (const re of ENDORSEMENT_PATTERNS) {
    const m = re.exec(text);
    if (m) out.push({ match: m[0], index: m.index });
  }
  return out;
}

/** AI assistant endpoints that accept a prefilled prompt in the URL. */
export const AI_ASSISTANT_HOSTS: Array<{ host: RegExp; name: string; params: string[] }> = [
  { host: /^(www\.)?chatgpt\.com$|^chat\.openai\.com$/, name: 'ChatGPT', params: ['q', 'prompt'] },
  { host: /^(www\.)?claude\.ai$/, name: 'Claude', params: ['q', 'prompt'] },
  { host: /^(www\.)?perplexity\.ai$/, name: 'Perplexity', params: ['q', 'query'] },
  { host: /^gemini\.google\.com$/, name: 'Gemini', params: ['q', 'prompt', 'text'] },
  { host: /^copilot\.microsoft\.com$|^(www\.)?bing\.com$/, name: 'Microsoft Copilot', params: ['q', 'prompt'] },
  { host: /^(www\.)?grok\.com$|^(www\.)?x\.com$/, name: 'Grok', params: ['q', 'text'] },
  { host: /^(www\.)?meta\.ai$/, name: 'Meta AI', params: ['q', 'prompt'] },
  { host: /^chat\.mistral\.ai$/, name: 'Mistral Le Chat', params: ['q'] },
  { host: /^chat\.deepseek\.com$/, name: 'DeepSeek', params: ['q'] },
  { host: /^(www\.)?you\.com$/, name: 'You.com', params: ['q'] },
  { host: /^(www\.)?poe\.com$/, name: 'Poe', params: ['q', 'prompt'] },
];

export function extractAiPrefill(url: URL): { assistant: string; param: string; prompt: string } | undefined {
  const host = url.hostname.toLowerCase();
  const entry = AI_ASSISTANT_HOSTS.find((h) => h.host.test(host));
  if (!entry) return undefined;
  // bing.com/x.com only count on their AI paths.
  if (/bing\.com$/.test(host) && !/^\/(chat|copilotsearch)/.test(url.pathname)) return undefined;
  if (/(^|\.)x\.com$/.test(host) && !/^\/i\/grok/.test(url.pathname)) return undefined;
  for (const param of entry.params) {
    const v = url.searchParams.get(param);
    if (v && v.trim().length > 0) return { assistant: entry.name, param, prompt: v };
  }
  // Some integrations put the prompt in the fragment (#q=...).
  if (url.hash.length > 1) {
    const hp = new URLSearchParams(url.hash.slice(1));
    for (const param of entry.params) {
      const v = hp.get(param);
      if (v && v.trim()) return { assistant: entry.name, param: `#${param}`, prompt: v };
    }
  }
  return undefined;
}

export const AI_LINK_RE = /https?:\/\/(?:www\.)?(?:chatgpt\.com|chat\.openai\.com|claude\.ai|perplexity\.ai|gemini\.google\.com|copilot\.microsoft\.com|bing\.com\/(?:chat|copilotsearch)|grok\.com|x\.com\/i\/grok|meta\.ai|chat\.mistral\.ai|chat\.deepseek\.com|you\.com|poe\.com)[^\s"'<>`)]*/gi;
