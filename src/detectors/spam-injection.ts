import { matchSpamKeywords, spamTopicCounts, TOPIC_THRESHOLD, type SpamCategory } from '../analysis/keywords.js';
import { foldForMatching } from '../analysis/text-normalizer.js';
import { isCrossSite, registrableDomain } from '../analysis/url-utils.js';
import { excerptAround, makeFinding } from '../risk/evidence.js';
import type { Detector } from '../types/detector.js';
import type { DraftFinding, Evidence } from '../types/finding.js';

/** Common embed providers; visible iframes from these are not reported. */
const EMBED_ALLOWLIST = /(^|\.)(youtube\.com|youtube-nocookie\.com|vimeo\.com|google\.com|googletagmanager\.com|doubleclick\.net|facebook\.com|twitter\.com|x\.com|instagram\.com|linkedin\.com|spotify\.com|soundcloud\.com|maps\.google\.com|openstreetmap\.org|codepen\.io|stripe\.com|paypal\.com|hcaptcha\.com|recaptcha\.net|cloudflare\.com|calendly\.com|typeform\.com|hubspot\.com|intercom\.io|loom\.com|figma\.com|wistia\.com|twitch\.tv|tiktok\.com)$/i;

const OBFUSCATION_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode|function\s*\(p,\s*a,\s*c,\s*k,\s*e)/i, label: 'eval of decoded/packed string' },
  { re: /new\s+Function\s*\(\s*(atob|unescape|decodeURIComponent)/i, label: 'Function constructor on decoded string' },
  // document.write of links/iframes, or of scripts from another host (local CDN fallbacks like '/static/jquery.js' are fine).
  { re: /document\.write\s*\([^)]*<\s*(a\s[^>]*href|iframe)\b/i, label: 'document.write of links/iframes' },
  { re: /document\.write\s*\([^)]*<\s*script[^>]*src\s*=\s*\\?["']?(https?:)?\/\//i, label: 'document.write of an external script' },
  { re: /(String\.fromCharCode\([^)]{0,40}\)[\s+]*){5,}/i, label: 'chained String.fromCharCode' },
  { re: /(\\x[0-9a-f]{2}){40,}/i, label: 'long hex-escaped string' },
  { re: /atob\s*\(\s*["'][A-Za-z0-9+/=]{200,}["']\s*\)/, label: 'large base64 payload decoded at runtime' },
];

export const spamInjectionDetector: Detector = {
  name: 'spam-injection',
  run(ctx) {
    const page = ctx.page;
    if (!page) return [];
    const findings: DraftFinding[] = [];
    const topic = spamTopicCounts(`${page.title ?? ''} ${page.visible_text}`);
    const isTopical = (c: SpamCategory): boolean => topic[c] >= TOPIC_THRESHOLD;

    // SPM-001 visible external links with spam keywords, grouped by category.
    const byCategory = new Map<SpamCategory, Evidence[]>();
    for (const link of page.links) {
      if (!link.external || link.hidden) continue; // hidden ones are HID-002
      const linkFold = foldForMatching(`${link.text} ${link.title ?? ''}`);
      for (const m of matchSpamKeywords(`${linkFold.folded} ${link.href}`)) {
        const list = byCategory.get(m.category) ?? [];
        list.push({ location: link.selector, source: 'link', excerpt: link.text || link.href, details: { href: link.href, domain: link.domain, matched: m.terms, ...(linkFold.transforms.length ? { obfuscation: linkFold.transforms } : {}) } });
        byCategory.set(m.category, list);
      }
    }
    for (const [category, ev] of byCategory) {
      const topical = isTopical(category);
      findings.push(
        makeFinding('SPM-001', {
          title: `External ${category.replace('_', '/')} link(s) detected`,
          severity: topical ? 'low' : ev.length >= 3 ? 'high' : 'medium',
          confidence: topical ? 'low' : 'medium',
          explanation: `${ev.length} visible outbound link(s) match ${category} keywords.${topical ? ' The page itself appears to be about this topic, so these may be editorial links.' : ' The visible page content does not appear to be about this topic.'}`,
          observed_behaviour: `Links to ${[...new Set(ev.map((e) => e.details?.domain))].join(', ')}`,
          evidence: ev,
        }),
      );
    }

    // SPM-002 hidden / unexpected external iframes
    for (const f of page.iframes) {
      if (!f.external || !/^https?:/i.test(f.src)) continue;
      const host = f.host ?? '';
      if (f.hidden) {
        findings.push(
          makeFinding('SPM-002', {
            severity: EMBED_ALLOWLIST.test(host) ? 'low' : 'high',
            confidence: EMBED_ALLOWLIST.test(host) ? 'low' : 'medium',
            explanation: `A hidden iframe loads content from ${host} (${f.hidden_reason ?? 'hidden'}).`,
            observed_behaviour: 'Third-party content is loaded invisibly.',
            evidence: [{ location: f.selector, source: 'iframe', visibility: `hidden: ${f.hidden_reason ?? 'hidden'}`, details: { src: f.src } }],
          }),
        );
      } else if (!EMBED_ALLOWLIST.test(host)) {
        const spam = matchSpamKeywords(f.src).length > 0;
        findings.push(
          makeFinding('SPM-002', {
            title: 'External iframe from an uncommon host',
            severity: spam ? 'high' : 'low',
            confidence: 'low',
            explanation: `A visible iframe embeds content from ${host}, which is not a commonly used embed provider.`,
            observed_behaviour: 'Third-party content embedded in the page.',
            evidence: [{ location: f.selector, source: 'iframe', details: { src: f.src } }],
          }),
        );
      }
    }

    // SPM-003 obfuscated inline scripts
    for (const s of page.scripts) {
      if (!s.inline) continue;
      const hits = OBFUSCATION_PATTERNS.filter((p) => p.re.test(s.inline!));
      if (!hits.length) continue;
      const first = hits[0]!.re.exec(s.inline)!;
      const navigates = /location(\.href)?\s*=|location\.replace|window\.open/.test(s.inline);
      findings.push(
        makeFinding('SPM-003', {
          severity: navigates ? 'high' : 'medium',
          explanation: `Inline script matches obfuscation pattern(s): ${hits.map((h) => h.label).join(', ')}.${navigates ? ' It also changes page location.' : ''} The script was not executed.`,
          observed_behaviour: 'Obfuscated code in page source.',
          evidence: [{ location: s.selector, source: 'script', excerpt: excerptAround(s.inline, first.index, first[0].length, 240) }],
        }),
      );
    }

    // MET-001 spam keywords in title/metadata
    const metaSources: Array<{ key: string; value: string; location: string }> = [];
    if (page.title) metaSources.push({ key: 'title', value: page.title, location: 'head > title' });
    for (const m of page.meta) {
      if (['description', 'keywords', 'og:title', 'og:description', 'twitter:title', 'twitter:description'].includes(m.key)) {
        metaSources.push({ key: m.key, value: m.content, location: m.selector });
      }
    }
    const metaEvidence: Evidence[] = [];
    let offTopic = false;
    for (const src of metaSources) {
      const matches = matchSpamKeywords(foldForMatching(src.value).folded);
      if (!matches.length) continue;
      const visibleCounts = spamTopicCounts(page.visible_text);
      if (matches.some((m) => visibleCounts[m.category] === 0)) offTopic = true;
      metaEvidence.push({ location: src.location, source: 'meta', excerpt: src.value, details: { field: src.key, matched: matches.flatMap((m) => m.terms) } });
    }
    if (metaEvidence.length) {
      findings.push(
        makeFinding('MET-001', {
          severity: offTopic ? 'high' : 'low',
          confidence: offTopic ? 'medium' : 'low',
          explanation: offTopic
            ? 'Title/metadata contain high-risk commercial keywords that do not appear in the visible page content — a common sign of metadata hijacking.'
            : 'Title/metadata contain high-risk commercial keywords that are also present in the visible content.',
          observed_behaviour: 'Metadata keywords inconsistent with page subject.',
          evidence: metaEvidence,
        }),
      );
    }

    // MET-002 cross-domain canonical
    if (page.canonical && /^https?:/.test(page.canonical) && isCrossSite(page.canonical, page.url)) {
      const spam = matchSpamKeywords(page.canonical).length > 0;
      findings.push(
        makeFinding('MET-002', {
          severity: spam ? 'high' : 'medium',
          explanation: `The canonical URL points to ${registrableDomain(page.canonical)}, not ${registrableDomain(page.url)}.`,
          observed_behaviour: `<link rel="canonical" href="${page.canonical}">`,
          evidence: [{ location: 'link[rel=canonical]', source: 'meta', details: { canonical: page.canonical } }],
        }),
      );
    }
    return findings;
  },
};
