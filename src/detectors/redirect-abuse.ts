import type { PageSnapshot } from '../analysis/html-parser.js';
import { matchSpamKeywords } from '../analysis/keywords.js';
import { findExternalUrlParams, isCrossSite, registrableDomain, resolveUrl } from '../analysis/url-utils.js';
import { getRule } from '../rules/catalog.js';
import { excerptAround, makeFinding, raiseSeverity } from '../risk/evidence.js';
import type { Detector, DetectorContext } from '../types/detector.js';
import type { DraftFinding, Evidence } from '../types/finding.js';
import type { DeclaredRedirect } from '../types/scan.js';

const JS_NAV_RES = [
  /(?:window\.|document\.|top\.|self\.|parent\.)?location(?:\.href)?\s*=\s*["'`]([^"'`]+)["'`]/g,
  /location\.(?:replace|assign)\(\s*["'`]([^"'`]+)["'`]\s*\)/g,
];

/** Extracts meta-refresh and simple JS navigation targets from a parsed page (static; nothing executes). */
export function extractDeclaredRedirects(page: PageSnapshot): DeclaredRedirect[] {
  const out: DeclaredRedirect[] = [];
  for (const m of page.meta_refresh) {
    const target = /url\s*=\s*['"]?([^'"\s;]+)/i.exec(m.content)?.[1];
    const resolved = target ? resolveUrl(target, page.url)?.href : undefined;
    if (resolved) out.push({ kind: 'meta_refresh', target: resolved, location: m.selector, excerpt: m.content });
  }
  for (const s of page.scripts) {
    if (!s.inline) continue;
    for (const re of JS_NAV_RES) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(s.inline))) {
        const resolved = resolveUrl(m[1] ?? '', page.url);
        if (resolved && /^https?:$/.test(resolved.protocol)) {
          out.push({ kind: 'javascript', target: resolved.href, location: s.selector, excerpt: excerptAround(s.inline, m.index, m[0].length, 200) });
        }
      }
    }
  }
  return out;
}

const HOST = String.raw`(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}`;
/** Link text that IS a hostname/URL ("www.paypal.com", "https://bank.com/login"). */
const WHOLE_HOST_RE = new RegExp(String.raw`^(?:https?:\/\/)?(${HOST})(?::\d+)?(?:[/?#]\S*)?$`, 'i');
/** An explicit URL or www-host inside longer link text. */
const EMBEDDED_URL_RE = new RegExp(String.raw`(?:https?:\/\/|\bwww\.)(${HOST})`, 'i');

/** Returns the hostname a link's text displays, if the text clearly presents one. */
export function displayedHost(text: string): string | undefined {
  const t = text.trim();
  const whole = WHOLE_HOST_RE.exec(t);
  // Bare tokens like "cs.CR", "Node.js" or "Shop.dev" are labels/product names, not displayed hostnames:
  // without a scheme or www, require an all-lowercase host.
  const explicit = /^(https?:\/\/|www\.)/i.test(t);
  if (whole && (explicit || whole[1] === whole[1]!.toLowerCase())) return whole[1]!.toLowerCase().replace(/^www\./, '');
  const embedded = EMBEDDED_URL_RE.exec(t);
  return embedded ? embedded[1]!.toLowerCase() : undefined;
}

function hopEvidence(ctx: DetectorContext): Evidence[] {
  return ctx.fetch.hops.map((h) => ({
    location: `redirect hop ${h.hop}`,
    source: 'redirect_chain' as const,
    details: { url: h.url, status: h.status, ...(h.location ? { location: h.location } : {}), kind: h.kind },
  }));
}

export const redirectAbuseDetector: Detector = {
  name: 'redirect-abuse',
  run(ctx) {
    const findings: DraftFinding[] = [];
    const { fetch, page } = ctx;
    const requested = fetch.requested_url;
    const redirected = fetch.hops.length > 1 || fetch.chain_error !== undefined;

    // RED-001 cross-domain redirect
    if (redirected && isCrossSite(requested, fetch.final_url)) {
      const finalDomain = registrableDomain(fetch.final_url) ?? '';
      const spam = matchSpamKeywords(`${fetch.final_url} ${finalDomain}`);
      findings.push(
        makeFinding('RED-001', {
          severity: spam.length ? 'high' : 'medium',
          explanation: `Requesting ${registrableDomain(requested)} ended on ${finalDomain} after ${fetch.hops.length - 1} redirect hop(s).`,
          observed_behaviour: `${requested} → ${fetch.final_url}`,
          evidence: hopEvidence(ctx),
        }),
      );
    }

    // RED-002 open redirect: a parameter's external URL became a hop destination
    const chainUrls = fetch.hops.map((h) => h.url).concat(fetch.final_url);
    for (let i = 0; i < fetch.hops.length; i++) {
      const hop = fetch.hops[i]!;
      if (!hop.location) continue;
      const hopUrl = resolveUrl(hop.url, hop.url);
      const next = resolveUrl(hop.location, hop.url);
      if (!hopUrl || !next) continue;
      for (const p of findExternalUrlParams(hopUrl)) {
        if (registrableDomain(next.href) === p.domain) {
          const exact = next.href === p.value || chainUrls.includes(p.value);
          findings.push(
            makeFinding('RED-002', {
              confidence: exact ? 'high' : 'medium',
              explanation: `Parameter "${p.name}" contained an external URL on ${p.domain}, and the server redirected to that domain.`,
              observed_behaviour: `${hop.url} → ${next.href}`,
              evidence: [
                { location: `query parameter "${p.name}"`, source: 'redirect_chain', details: { parameter_value: p.value } },
                ...hopEvidence(ctx),
              ],
            }),
          );
        }
      }
    }

    // RED-005 loops / too many redirects
    if (fetch.chain_error) {
      findings.push(
        makeFinding('RED-005', {
          explanation: fetch.chain_error === 'redirect_loop' ? 'The redirect chain revisits a URL it already visited.' : 'The redirect chain exceeded the maximum number of hops.',
          observed_behaviour: `${fetch.hops.length} hop(s) recorded before stopping (${fetch.chain_error}).`,
          evidence: hopEvidence(ctx),
        }),
      );
    }

    // RED-007 https -> http downgrade
    for (const hop of fetch.hops) {
      if (!hop.location) continue;
      const next = resolveUrl(hop.location, hop.url);
      if (hop.url.startsWith('https:') && next?.protocol === 'http:') {
        findings.push(
          makeFinding('RED-007', {
            explanation: 'A secure HTTPS URL redirects to an insecure HTTP URL.',
            observed_behaviour: `${hop.url} → ${next.href}`,
            evidence: [{ location: `redirect hop ${hop.hop}`, source: 'redirect_chain', details: { url: hop.url, location: hop.location, status: hop.status } }],
          }),
        );
      }
    }

    if (!page) return findings;

    // RED-004 declared client-side redirects to other domains
    for (const d of ctx.declaredRedirects) {
      if (!isCrossSite(d.target, page.url)) continue;
      const spam = matchSpamKeywords(d.target);
      const zeroDelay = d.kind === 'meta_refresh' && /^\s*0\s*[;,]/.test(d.excerpt);
      let severity = getRule('RED-004').default_severity;
      if (spam.length || zeroDelay) severity = raiseSeverity(severity);
      findings.push(
        makeFinding('RED-004', {
          severity,
          confidence: d.kind === 'meta_refresh' ? 'high' : 'medium',
          explanation: `The page declares a ${d.kind === 'meta_refresh' ? 'meta refresh' : 'JavaScript navigation'} to ${registrableDomain(d.target)}. ${d.kind === 'javascript' ? 'The script was not executed; the redirect may be conditional or unreachable.' : ''}`.trim(),
          observed_behaviour: `${page.url} declares navigation to ${d.target}`,
          evidence: [{ location: d.location, source: d.kind === 'meta_refresh' ? 'meta' : 'script', excerpt: d.excerpt, details: { target: d.target } }],
        }),
      );
    }

    // RED-008 conditional (referrer/UA) client-side redirect logic
    for (const s of page.scripts) {
      if (!s.inline) continue;
      const code = s.inline;
      const checksReferrer = /document\.referrer/.test(code);
      const checksUa = /navigator\.userAgent/.test(code);
      const navigates = /location(\.href)?\s*=|location\.(replace|assign)\(|window\.open\(/.test(code);
      if (!(checksReferrer || checksUa) || !navigates) continue;
      const searchTerms = /google|bing|yahoo|duckduckgo|baidu|yandex|search|bot|crawler|spider|chatgpt|perplexity|claude/i.exec(code);
      const idx = code.search(/document\.referrer|navigator\.userAgent/);
      findings.push(
        makeFinding('RED-008', {
          severity: searchTerms ? 'high' : 'medium',
          confidence: searchTerms ? 'medium' : 'low',
          explanation: `An inline script inspects ${[checksReferrer && 'document.referrer', checksUa && 'navigator.userAgent'].filter(Boolean).join(' and ')} and changes the page location${searchTerms ? `, referencing "${searchTerms[0]}"` : ''}. The script was not executed.`,
          observed_behaviour: 'Conditional navigation logic present in page source.',
          evidence: [{ location: s.selector, source: 'script', excerpt: excerptAround(code, Math.max(0, idx), 60, 300) }],
        }),
      );
    }

    // RED-003 links to same-site redirect endpoints carrying external destinations
    const red003: Evidence[] = [];
    let red003Spam = false;
    for (const link of page.links) {
      if (!link.is_http || link.external) continue;
      const u = resolveUrl(link.href, page.url);
      if (!u) continue;
      for (const p of findExternalUrlParams(u)) {
        if (matchSpamKeywords(`${p.value} ${link.text}`).length) red003Spam = true;
        red003.push({ location: link.selector, source: 'link', excerpt: link.text, details: { href: link.href, parameter: p.name, destination: p.value } });
      }
    }
    if (red003.length) {
      findings.push(
        makeFinding('RED-003', {
          severity: red003Spam ? 'medium' : 'low',
          explanation: `${red003.length} on-page link(s) route through a same-site URL that carries an external destination in its query string. These endpoints were not requested.`,
          observed_behaviour: 'Possible redirect endpoint accepting arbitrary destinations.',
          evidence: red003,
        }),
      );
    }

    // RED-006 deceptive link text
    for (const link of page.links) {
      if (!link.is_http || !link.domain) continue;
      const host = displayedHost(link.text);
      if (!host) continue;
      // Text that is part of the destination URL itself (e.g. arxiv.org/archive/cs.CR) is a label, not a disguise.
      if (link.href.toLowerCase().includes(link.text.trim().toLowerCase())) continue;
      const shown = registrableDomain(host);
      if (!shown || shown === link.domain) continue;
      // A same-site wrapper whose parameter points to the shown domain is a tracker, not deception.
      const u = resolveUrl(link.href, page.url);
      const wrapsShown = u ? findExternalUrlParams(u).some((p) => p.domain === shown) : false;
      const spam = matchSpamKeywords(link.href).length > 0;
      findings.push(
        makeFinding('RED-006', {
          severity: spam ? 'high' : wrapsShown ? 'low' : 'medium',
          confidence: wrapsShown ? 'low' : 'medium',
          explanation: `Link text displays "${shown}" but the link points to ${link.domain}${wrapsShown ? ' (through a redirect wrapper that carries the shown domain)' : ''}.`,
          observed_behaviour: `Displayed: ${shown}; actual destination: ${link.href}`,
          evidence: [{ location: link.selector, source: 'link', excerpt: link.text, details: { href: link.href } }],
        }),
      );
    }

    return findings;
  },
};
