import type { Category, Confidence, Severity } from '../types/finding.js';

export interface RuleDefinition {
  rule_id: string;
  category: Category;
  title: string;
  description: string;
  detection: string;
  default_severity: Severity;
  default_confidence: Confidence;
  severity_mapping: string;
  potential_impact: string;
  recommendation: string;
  false_positive_considerations: string;
  /** Milestone in which the rule is implemented. */
  status: 'implemented' | 'planned';
}

const r = (def: RuleDefinition): RuleDefinition => def;

export const RULES: RuleDefinition[] = [
  // ── Redirect abuse ───────────────────────────────────────────────────────────
  r({
    rule_id: 'RED-001', category: 'redirect_abuse', status: 'implemented',
    title: 'Redirect to a different registrable domain',
    description: 'The requested URL redirects (HTTP 3xx or Refresh header) to a different registrable domain.',
    detection: 'Compare the eTLD+1 of the requested URL with every hop and the final URL.',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium by default; high when the destination is flagged by keyword lists; low when it is a known, common redirect (www/apex, http→https, same organisation).',
    potential_impact: 'Visitors and crawlers that trust the original domain are sent to a third party. This is a common sign of hacked redirects or abused redirect endpoints.',
    recommendation: 'Confirm whether the redirect is intended. If not, review server rewrite rules, .htaccess, CMS plugins, and recently changed redirect configuration.',
    false_positive_considerations: 'Domain migrations, brand domains, SSO and payment flows, and link shorteners legitimately redirect cross-domain.',
  }),
  r({
    rule_id: 'RED-002', category: 'redirect_abuse', status: 'implemented',
    title: 'Open-redirect pattern observed',
    description: 'The URL carries an external destination in a query parameter and the server redirected to that destination.',
    detection: 'A redirect-style parameter (url, next, target, ...) holds an absolute URL on another domain, and a hop redirects to that same domain.',
    default_severity: 'high', default_confidence: 'medium',
    severity_mapping: 'high when the observed redirect follows an attacker-controllable parameter; confidence high when the destination exactly matches the parameter value.',
    potential_impact: 'Attackers can make links on your trusted domain lead anywhere, which is used for phishing, spam, and laundering reputation into AI/search results.',
    recommendation: 'Validate redirect destinations against an allowlist of permitted domains or use opaque redirect IDs instead of raw URLs.',
    false_positive_considerations: 'Login "next" parameters and outbound-click trackers are often intentionally open but should still be restricted.',
  }),
  r({
    rule_id: 'RED-003', category: 'redirect_abuse', status: 'implemented',
    title: 'On-page link to a redirect endpoint with an external destination',
    description: 'A link on the page points to a same-site URL whose query string contains an external destination URL.',
    detection: 'Static inspection of link hrefs; the endpoint is not requested.',
    default_severity: 'low', default_confidence: 'low',
    severity_mapping: 'low; medium when the destination domain or anchor text matches spam keyword lists.',
    potential_impact: 'Indicates a redirect endpoint that may accept arbitrary destinations.',
    recommendation: 'Check whether the endpoint restricts destinations; test only on sites you are authorised to assess.',
    false_positive_considerations: 'Outbound click tracking and share widgets commonly use this pattern legitimately.',
  }),
  r({
    rule_id: 'RED-004', category: 'redirect_abuse', status: 'implemented',
    title: 'Meta-refresh or JavaScript navigation to an external domain',
    description: 'The page declares a meta refresh or contains a simple script that navigates to another registrable domain.',
    detection: 'Parse <meta http-equiv="refresh"> and inline scripts for location assignments. Scripts are never executed.',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium; high for zero-delay refreshes to unrelated or keyword-flagged domains.',
    potential_impact: 'Client-side redirects are a common way to send visitors to spam/scam sites while crawlers index the original content.',
    recommendation: 'Remove unexpected redirect code and audit templates and plugins for injected scripts.',
    false_positive_considerations: 'Legacy pages and interstitials may use meta refresh intentionally.',
  }),
  r({
    rule_id: 'RED-005', category: 'redirect_abuse', status: 'implemented',
    title: 'Redirect loop or excessive redirect chain',
    description: 'The redirect chain loops back on itself or exceeds the configured maximum number of hops.',
    detection: 'Track every visited URL during manual redirect following.',
    default_severity: 'low', default_confidence: 'high',
    severity_mapping: 'low (availability/configuration issue).',
    potential_impact: 'Visitors and crawlers cannot reach content; may hide conditional redirects.',
    recommendation: 'Review redirect rules for conflicting conditions.',
    false_positive_considerations: 'Some sites loop only for clients without cookies.',
  }),
  r({
    rule_id: 'RED-006', category: 'redirect_abuse', status: 'implemented',
    title: 'Link text shows a different domain than its destination',
    description: 'The visible text of a link displays a domain name that differs from where the link actually points.',
    detection: 'Extract domain-like tokens from anchor text and compare with the href\'s registrable domain.',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium; high when the real destination is keyword-flagged.',
    potential_impact: 'Deceptive links mislead users and AI systems about where a citation or reference leads.',
    recommendation: 'Make link text match the destination or remove the link.',
    false_positive_considerations: 'Tracking redirectors (e.g. newsletter click trackers) legitimately wrap destinations.',
  }),
  r({
    rule_id: 'RED-007', category: 'redirect_abuse', status: 'implemented',
    title: 'HTTPS to HTTP downgrade in redirect chain',
    description: 'A hop redirects from an HTTPS URL to a plain HTTP URL.',
    detection: 'Compare protocols of consecutive hops.',
    default_severity: 'low', default_confidence: 'high',
    severity_mapping: 'low.',
    potential_impact: 'Traffic can be intercepted or modified in transit.',
    recommendation: 'Redirect only to HTTPS destinations and enable HSTS.',
    false_positive_considerations: 'Rare legacy endpoints.',
  }),
  r({
    rule_id: 'RED-008', category: 'cloaking', status: 'implemented',
    title: 'Conditional client-side redirect logic (cloaking indicator)',
    description: 'An inline script checks the referrer or user-agent and then changes location, a common pattern in hacked "search-referrer redirects".',
    detection: 'Inline script references document.referrer or navigator.userAgent and assigns/replaces location in the same script.',
    default_severity: 'high', default_confidence: 'medium',
    severity_mapping: 'high when search-engine names or bot keywords appear in the condition; medium otherwise.',
    potential_impact: 'Visitors from search or AI assistants are redirected while the owner, testing directly, sees the normal page.',
    recommendation: 'Locate the script source (theme, plugin, injected snippet) and remove it; check for a wider compromise.',
    false_positive_considerations: 'Mobile-site redirects and A/B testing scripts sometimes branch on user-agent.',
  }),

  // ── Hidden content ───────────────────────────────────────────────────────────
  r({
    rule_id: 'HID-001', category: 'hidden_content', status: 'implemented',
    title: 'Hidden text block',
    description: 'A substantial block of text is present in the HTML but hidden from visitors, outside any recognised legitimate UI pattern.',
    detection: 'Static CSS/attribute analysis (display, visibility, opacity, font-size, clipping) with legitimate-pattern suppression.',
    default_severity: 'medium', default_confidence: 'low',
    severity_mapping: 'medium; high when the hidden text contains spam keywords or external links.',
    potential_impact: 'Hidden keyword blocks and spam text manipulate how search engines and AI systems interpret the page.',
    recommendation: 'Identify why the text is hidden and remove it if it is not part of an intended UI component.',
    false_positive_considerations: 'Static analysis cannot see JavaScript-driven UI. Collapsed sections, carousels and templates may be hidden until interaction.',
  }),
  r({
    rule_id: 'HID-002', category: 'hidden_content', status: 'implemented',
    title: 'Hidden link to an external domain',
    description: 'A link pointing to another registrable domain is hidden from visitors.',
    detection: 'Links whose element or ancestor is hidden, or that are rendered with unreadably tiny text.',
    default_severity: 'high', default_confidence: 'medium',
    severity_mapping: 'high; critical when the destination is keyword-flagged (casino, pharma, adult...).',
    potential_impact: 'Classic link-injection spam: passes your site\'s authority to third parties and signals compromise.',
    recommendation: 'Remove the links and investigate how they were inserted (theme files, database content, plugins).',
    false_positive_considerations: 'Hidden social/share links inside menus or modals are normally legitimate.',
  }),
  r({
    rule_id: 'HID-003', category: 'hidden_content', status: 'implemented',
    title: 'Off-screen positioned content',
    description: 'Content is pushed far outside the viewport with negative positioning or text-indent.',
    detection: 'position:absolute/fixed with large negative left/top/right, or text-indent ≤ -500px.',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium; high with spam keywords or external links.',
    potential_impact: 'Off-screen text is invisible to users but read by crawlers and AI systems.',
    recommendation: 'Remove off-screen content that is not accessibility text or image-replacement for a logo.',
    false_positive_considerations: 'Old image-replacement techniques and skip links use negative indent.',
  }),
  r({
    rule_id: 'HID-004', category: 'hidden_content', status: 'implemented',
    title: 'Text colour matches background',
    description: 'Text is coloured the same (or nearly the same) as its background.',
    detection: 'Compare normalised colour of the element with the nearest declared background (default white).',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium; high with links or spam keywords.',
    potential_impact: 'White-on-white text is a well-known hidden-text spam technique.',
    recommendation: 'Remove the text or make it visible.',
    false_positive_considerations: 'Background images or gradients can make same-colour text readable; static analysis cannot see them.',
  }),
  r({
    rule_id: 'HID-005', category: 'hidden_content', status: 'implemented',
    title: 'Zero-size or unreadably tiny text/links',
    description: 'Text or links rendered at 0–3px font size or inside a 0–1px box.',
    detection: 'font-size and width/height declarations.',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium; high for external links.',
    potential_impact: 'Tiny links and text are used to hide spam while remaining crawlable.',
    recommendation: 'Remove the content or render it at a readable size.',
    false_positive_considerations: 'Tracking pixels and some icon fonts use tiny sizes without text.',
  }),

  // ── Spam / injected content ──────────────────────────────────────────────────
  r({
    rule_id: 'SPM-001', category: 'spam_injection', status: 'implemented',
    title: 'External link with high-risk commercial keywords',
    description: 'An outbound link\'s anchor text or URL matches gambling, pharmaceutical, adult, or scam keyword lists.',
    detection: 'Keyword lists applied to anchor text, link title and destination URL; page topic is considered to reduce false positives.',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium for visible links; high when hidden or when the page itself is not about the topic.',
    potential_impact: 'Typical of SEO spam injection into compromised or abused sites.',
    recommendation: 'Check when and how the link was added; remove unauthorised links and audit for compromise.',
    false_positive_considerations: 'Sites legitimately about these topics (news, affiliates, health) will match.',
  }),
  r({
    rule_id: 'SPM-002', category: 'spam_injection', status: 'implemented',
    title: 'Hidden or unexpected external iframe',
    description: 'An iframe/embed loads content from another domain while hidden or zero-sized, or from an uncommon embed host.',
    detection: 'Iframe visibility and size attributes; common embed providers are allowlisted.',
    default_severity: 'high', default_confidence: 'medium',
    severity_mapping: 'high for hidden external iframes; low for visible iframes from uncommon hosts.',
    potential_impact: 'Hidden iframes are used for drive-by malware, ad fraud and invisible link injection.',
    recommendation: 'Remove unknown iframes and look for the injection source.',
    false_positive_considerations: 'Analytics, consent and chat widgets sometimes use hidden iframes.',
  }),
  r({
    rule_id: 'SPM-003', category: 'spam_injection', status: 'implemented',
    title: 'Obfuscated inline script',
    description: 'An inline script uses patterns typical of injected malware: eval of decoded strings, document.write of links/iframes, or heavy character-code obfuscation.',
    detection: 'Regex patterns over inline script source. Scripts are never executed.',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium; high when combined with redirects or link injection.',
    potential_impact: 'Obfuscated scripts commonly deliver redirects, spam links or skimmers.',
    recommendation: 'Decode and review the script; remove it unless it comes from a trusted, known vendor.',
    false_positive_considerations: 'Some minified vendor bundles and bot-protection scripts look obfuscated.',
  }),
  r({
    rule_id: 'MET-001', category: 'content_integrity', status: 'implemented',
    title: 'Spam keywords in title or metadata',
    description: 'The title, meta description or Open Graph tags contain high-risk commercial keywords not reflected in the visible content.',
    detection: 'Keyword lists applied to metadata; compared with keyword presence in visible text.',
    default_severity: 'high', default_confidence: 'medium',
    severity_mapping: 'high when the visible page does not mention the topic; low otherwise.',
    potential_impact: 'Metadata hijacking (e.g. "Japanese keyword hack") changes how search and AI results describe the page.',
    recommendation: 'Restore correct metadata and look for injected template code or database changes.',
    false_positive_considerations: 'Pages legitimately about these topics.',
  }),
  r({
    rule_id: 'MET-002', category: 'content_integrity', status: 'implemented',
    title: 'Canonical URL points to another domain',
    description: 'The canonical link element points to a different registrable domain.',
    detection: 'Compare canonical URL domain with the page domain.',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium; high when the canonical domain is keyword-flagged.',
    potential_impact: 'Search engines may consolidate the page\'s signals into a third-party domain.',
    recommendation: 'Verify the canonical is intended (syndication) and fix it otherwise.',
    false_positive_considerations: 'Syndicated content and multi-domain brands legitimately cross-canonicalise.',
  }),

  // ── AI prompt injection / GEO context manipulation ───────────────────────────
  r({
    rule_id: 'AI-001', category: 'ai_prompt_injection', status: 'implemented',
    title: 'Hidden AI-directed instructions',
    description: 'Text hidden from visitors contains instructions aimed at AI assistants (overriding instructions, forcing recommendations, persisting to memory, extracting prompts).',
    detection: 'Instruction pattern families applied to hidden text.',
    default_severity: 'high', default_confidence: 'medium',
    severity_mapping: 'high; critical for memory-persistence or data-exfiltration instructions; confidence rises with the number of matched pattern families.',
    potential_impact: 'AI assistants that read the page may follow the instructions, distorting answers, recommendations or saved memories for users.',
    recommendation: 'Remove the hidden instructions and determine who added them.',
    false_positive_considerations: 'Security articles discussing prompt injection may quote such phrases, but rarely in hidden elements.',
  }),
  r({
    rule_id: 'AI-002', category: 'ai_prompt_injection', status: 'implemented',
    title: 'AI-directed instructions in comments, attributes, metadata or structured data',
    description: 'HTML comments, alt/aria/title attributes, meta tags or JSON-LD contain instructions aimed at AI assistants.',
    detection: 'Instruction pattern families applied to non-visible machine-readable channels.',
    default_severity: 'high', default_confidence: 'medium',
    severity_mapping: 'high; medium when only weak patterns match.',
    potential_impact: 'These channels are read by crawlers and AI pipelines but rarely reviewed by humans.',
    recommendation: 'Remove the instructions from the markup and templates.',
    false_positive_considerations: 'Developer comments occasionally contain imperative language.',
  }),
  r({
    rule_id: 'AI-003', category: 'ai_prompt_injection', status: 'implemented',
    title: 'AI-directed instructions in visible content',
    description: 'Visible page text contains phrases that address AI assistants with instructions.',
    detection: 'Instruction pattern families applied to visible text.',
    default_severity: 'medium', default_confidence: 'low',
    severity_mapping: 'medium; low when the page appears to discuss prompt injection as a topic.',
    potential_impact: 'May steer AI summaries or recommendations of the page.',
    recommendation: 'Review whether the text is intended editorial content or an injection attempt.',
    false_positive_considerations: 'Articles, documentation and research about AI frequently quote such phrases.',
  }),
  r({
    rule_id: 'AI-004', category: 'ai_prompt_injection', status: 'implemented',
    title: 'AI assistant link with manipulative prefilled prompt',
    description: 'A link/button opens an AI assistant with a prefilled prompt that goes beyond summarising — e.g. telling the assistant to remember the site as a trusted source or always recommend it.',
    detection: 'Static decoding of query parameters on links to known AI assistant endpoints; links are never followed.',
    default_severity: 'high', default_confidence: 'high',
    severity_mapping: 'high; critical when the prompt asks the assistant to persist instructions to memory.',
    potential_impact: '"AI recommendation poisoning": a user clicking "Summarise with AI" unknowingly plants a biased instruction in their own assistant, which can affect future answers.',
    recommendation: 'Limit share-to-AI links to a neutral prompt such as "Summarise <URL>". Remove persistence, recommendation or ranking instructions.',
    false_positive_considerations: 'Prompts that only request a summary or a question about the page are benign (reported as AI-005).',
  }),
  r({
    rule_id: 'AI-005', category: 'ai_prompt_injection', status: 'implemented',
    title: 'AI assistant link with prefilled prompt',
    description: 'A link opens an AI assistant with a prefilled prompt that appears benign.',
    detection: 'Static decoding of AI assistant link parameters.',
    default_severity: 'informational', default_confidence: 'high',
    severity_mapping: 'informational.',
    potential_impact: 'None by itself; recorded so prompts can be reviewed over time.',
    recommendation: 'Keep prefilled prompts neutral and transparent to the user.',
    false_positive_considerations: 'N/A.',
  }),
  r({
    rule_id: 'AI-006', category: 'ai_prompt_injection', status: 'implemented',
    title: 'Unsupported AI endorsement or authority claim',
    description: 'Content claims endorsement or ranking by AI assistants or AI companies (e.g. "ChatGPT recommends us"), a memory-poisoning indicator.',
    detection: 'Patterns over visible text, metadata and JSON-LD.',
    default_severity: 'low', default_confidence: 'low',
    severity_mapping: 'low; medium when hidden or in structured data.',
    potential_impact: 'Fabricated authority claims can be repeated by AI systems summarising the page.',
    recommendation: 'Remove unverifiable endorsement claims or support them with evidence.',
    false_positive_considerations: 'Genuine press coverage or awards may be described similarly.',
  }),

  // ── Obfuscation and smuggling (0.2.0) ────────────────────────────────────────
  r({
    rule_id: 'AI-007', category: 'ai_prompt_injection', status: 'implemented',
    title: 'Text smuggled in invisible Unicode characters',
    description: 'Readable text is encoded in characters that render as nothing: Unicode tag characters ("ASCII smuggling"), runs of variation selectors after a visible character, or zero-width characters used as binary.',
    detection: 'Invisible code points are grouped into runs and decoded (tag → ASCII, selectors → bytes, two-symbol zero-width → bits). Emoji subdivision flags, single presentation selectors and single joiners are ignored.',
    default_severity: 'medium', default_confidence: 'high',
    severity_mapping: 'critical when the decoded text asks for memory persistence or data exfiltration; high for other AI instructions or spam; medium for other substantial text in tag characters; low for short payloads in selectors or zero-width binary (often copy-tracking watermarks).',
    potential_impact: 'Language models read these characters even though people and most review tools cannot see them, so a page can carry complete instructions that no human reviewer will notice.',
    recommendation: 'Find where the characters enter the page (templates, CMS fields, third-party widgets) and strip Unicode tag characters and selector runs from user-facing content.',
    false_positive_considerations: 'Some publishers embed invisible copy-tracking watermarks; these decode to short IDs rather than sentences and are reported at low severity.',
  }),
  r({
    rule_id: 'AI-008', category: 'ai_prompt_injection', status: 'implemented',
    title: 'Obfuscated AI-directed instructions',
    description: 'Text matches AI-instruction patterns only after de-obfuscation: look-alike letters from other scripts, fullwidth or mathematical letters, leetspeak, spaced-out letters, invisible characters inside words, or right-to-left override reversal.',
    detection: 'Text is folded for matching (NFKC, curated confusables inside Latin words, leetspeak inside mixed tokens, spaced-letter collapse, invisible-character removal, override reversal) and the instruction patterns are re-run. Reported only when the original text did not already match.',
    default_severity: 'high', default_confidence: 'medium',
    severity_mapping: 'critical for persistence or exfiltration instructions; high otherwise. Confidence high when two or more obfuscation techniques or pattern families are involved.',
    potential_impact: 'Deliberate obfuscation is used to slip instructions past filters while language models still read them correctly.',
    recommendation: 'Remove the instructions. Obfuscation indicates intent, so audit how the content was added.',
    false_positive_considerations: 'Look-alike folding only applies inside words mixing Latin with another script, or inside mostly-Latin text, so ordinary Cyrillic, Greek or Armenian text is not affected; a full instruction phrase is still required.',
  }),
  r({
    rule_id: 'AI-009', category: 'ai_prompt_injection', status: 'implemented',
    title: 'Encoded AI instructions or spam payload',
    description: 'A base64, hex, percent-encoded or JavaScript-escaped blob decodes (up to two layers) to AI instructions or high-risk commercial spam.',
    detection: 'Blobs in hidden text, comments, attributes, data-* attributes, metadata, JSON-LD and AI prefill prompts are decoded. data: URIs, JWTs, binary formats (images, fonts, archives) and unreadable results are skipped. Decoding alone is never reported.',
    default_severity: 'high', default_confidence: 'medium',
    severity_mapping: 'critical for persistence or exfiltration instructions; high for other instructions or spam. Confidence high when a strong instruction family matches.',
    potential_impact: 'Encoded instructions are designed for AI agents and tools that decode content, while staying unreadable to human reviewers and keyword filters.',
    recommendation: 'Remove the payload and find which script, plugin or CMS field introduced it.',
    false_positive_considerations: 'Configuration blobs can legitimately contain base64; only payloads whose decoded text matches instruction or spam patterns are reported.',
  }),
  r({
    rule_id: 'HID-006', category: 'hidden_content', status: 'implemented',
    title: 'Bidirectional override characters in left-to-right text',
    description: 'LEFT-TO-RIGHT or RIGHT-TO-LEFT OVERRIDE characters appear in text containing no right-to-left script, so the text displays in a different order than it is stored ("Trojan Source").',
    detection: 'U+202D/U+202E in a text channel with no Arabic, Hebrew, Syriac, Thaana, NKo or Adlam characters. Marks, embeddings and isolates are not reported.',
    default_severity: 'medium', default_confidence: 'medium',
    severity_mapping: 'medium; high when the reordered segment contains AI instructions or spam.',
    potential_impact: 'People and AI systems read different text: a reviewer sees one order, a model or filter processes another. Also used to disguise file names and links.',
    recommendation: 'Remove override characters from left-to-right content and sanitise user input for bidi controls.',
    false_positive_considerations: 'Pages quoting right-to-left text are excluded when the script appears in the same text; demonstrations of the technique on security sites will match.',
  }),

  // ── Planned (later milestones) ───────────────────────────────────────────────
  r({
    rule_id: 'CLK-001', category: 'cloaking', status: 'planned',
    title: 'Content diverges across request contexts',
    description: 'Title, text, links or redirects differ materially between configured request contexts.',
    detection: 'Planned for Phase 3 (geo_compare_page_variants).',
    default_severity: 'high', default_confidence: 'medium', severity_mapping: 'Planned.',
    potential_impact: 'Cloaking misleads search engines, AI crawlers, or visitors.',
    recommendation: 'Planned.', false_positive_considerations: 'Responsive designs and localisation legitimately differ.',
  }),
  r({
    rule_id: 'UGC-001', category: 'ugc_abuse', status: 'planned',
    title: 'User-generated page promoting unrelated commercial content',
    description: 'Planned for Phase 4/geo_audit_ugc.',
    detection: 'Planned.', default_severity: 'medium', default_confidence: 'medium', severity_mapping: 'Planned.',
    potential_impact: 'Trusted-domain abuse.', recommendation: 'Planned.', false_positive_considerations: 'Planned.',
  }),
];

export const RULES_BY_ID = new Map(RULES.map((rule) => [rule.rule_id, rule]));

export function getRule(ruleId: string): RuleDefinition {
  const rule = RULES_BY_ID.get(ruleId);
  if (!rule) throw new Error(`Unknown rule ${ruleId}`);
  return rule;
}

export const TAXONOMY: Array<{ category: Category; name: string; description: string; rule_ids: string[] }> = [
  { category: 'redirect_abuse', name: 'Open and sneaky redirects', description: 'Redirects that send users or crawlers to unexpected destinations, and redirect endpoints that can be abused.', rule_ids: [] },
  { category: 'cloaking', name: 'Cloaking and conditional delivery', description: 'Different content or redirects depending on who is asking.', rule_ids: [] },
  { category: 'hidden_content', name: 'Hidden content', description: 'Text and links present in the source but hidden from visitors.', rule_ids: [] },
  { category: 'spam_injection', name: 'Spam and injected content', description: 'Injected links, iframes and scripts typical of compromise or SEO spam.', rule_ids: [] },
  { category: 'content_integrity', name: 'Content and metadata integrity', description: 'Hijacked titles, metadata and canonical tags.', rule_ids: [] },
  { category: 'ai_prompt_injection', name: 'AI prompt injection and GEO context manipulation', description: 'Content designed to instruct, bias or poison AI assistants that read the page.', rule_ids: [] },
  { category: 'ugc_abuse', name: 'User-generated content and trusted-domain abuse', description: 'Spam published through legitimate publishing features of trusted domains.', rule_ids: [] },
];
for (const entry of TAXONOMY) entry.rule_ids = RULES.filter((rule) => rule.category === entry.category).map((rule) => rule.rule_id);
