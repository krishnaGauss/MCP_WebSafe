import { getDomain, getHostname } from 'tldts';

/** Registrable domain (eTLD+1) for a URL or hostname; falls back to the hostname for IPs/unknown TLDs. */
export function registrableDomain(urlOrHost: string): string | undefined {
  const host = getHostname(urlOrHost) ?? undefined;
  if (!host) return undefined;
  return (getDomain(host, { allowPrivateDomains: true }) ?? host).toLowerCase();
}

export function hostnameOf(urlOrHost: string): string | undefined {
  return getHostname(urlOrHost)?.toLowerCase() ?? undefined;
}

/** True when two URLs belong to different registrable domains (subdomains of the same site are not external). */
export function isCrossSite(a: string, b: string): boolean {
  const da = registrableDomain(a);
  const db = registrableDomain(b);
  return !!da && !!db && da !== db;
}

export function resolveUrl(href: string, base: string): URL | undefined {
  try {
    return new URL(href.trim(), base);
  } catch {
    return undefined;
  }
}

export function isHttpUrl(u: URL | undefined): u is URL {
  return !!u && (u.protocol === 'http:' || u.protocol === 'https:');
}

/** Query parameter names commonly used by redirect endpoints. */
export const REDIRECT_PARAM_NAMES = new Set([
  'url', 'u', 'uri', 'target', 'dest', 'destination', 'redirect', 'redirect_to', 'redirect_uri', 'redirect_url', 'redirecturl',
  'next', 'return', 'returnto', 'return_to', 'returnurl', 'return_url', 'goto', 'go', 'out', 'link', 'r', 'to', 'continue',
  'forward', 'jump', 'q', 'site', 'view', 'ref_url', 'checkout_url', 'callback', 'image_url', 'path',
]);

/**
 * Finds query parameters whose value is an absolute http(s) URL on a different registrable domain.
 * Only names in REDIRECT_PARAM_NAMES are considered, plus any param whose value is clearly a URL.
 */
export function findExternalUrlParams(url: URL): Array<{ name: string; value: string; domain: string }> {
  const out: Array<{ name: string; value: string; domain: string }> = [];
  const own = registrableDomain(url.href);
  for (const [name, rawValue] of url.searchParams) {
    let value = rawValue.trim();
    // Some endpoints double-encode the destination.
    if (/^https?%3a/i.test(value)) {
      try {
        value = decodeURIComponent(value);
      } catch {
        /* keep raw */
      }
    }
    const looksLikeUrl = /^(https?:)?\/\/[^/\s]+/i.test(value);
    if (!looksLikeUrl && !REDIRECT_PARAM_NAMES.has(name.toLowerCase())) continue;
    if (!looksLikeUrl) continue;
    const target = resolveUrl(value.startsWith('//') ? `https:${value}` : value, url.href);
    if (!isHttpUrl(target)) continue;
    const domain = registrableDomain(target.href);
    if (domain && own && domain !== own) out.push({ name, value: target.href, domain });
  }
  return out;
}
