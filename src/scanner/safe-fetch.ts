import { Agent, request } from 'undici';
import type { SecurityPolicy } from '../config.js';
import { GeoShieldError, toGeoShieldError } from '../errors.js';
import { createGuardedLookup, validateTargetUrl } from '../security/ssrf-protection.js';
import type { FetchResult, RedirectHop } from '../types/scan.js';
import type { RequestContext } from './request-contexts.js';

export interface SafeFetchOptions {
  policy: SecurityPolicy;
  context: RequestContext;
  maxRedirects: number;
  timeoutMs: number;
  maxBodyBytes: number;
  /** When false, only headers are read (body is discarded) — used by redirect tracing. */
  readBody?: boolean;
}

const RECORDED_HEADERS = ['location', 'refresh', 'content-type', 'content-length', 'server', 'cache-control', 'x-robots-tag', 'link', 'vary', 'set-cookie'];
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function pickHeaders(raw: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of RECORDED_HEADERS) {
    const v = raw[name];
    if (v === undefined) continue;
    // Never retain cookie values; record only that a cookie was set.
    if (name === 'set-cookie') {
      out[name] = `[${Array.isArray(v) ? v.length : 1} cookie(s) set, values not stored]`;
      continue;
    }
    out[name] = (Array.isArray(v) ? v.join(', ') : v).slice(0, 500);
  }
  return out;
}

/** Parses a Refresh header value like `0; url=https://x` and returns the URL, if any. */
export function parseRefreshValue(value: string): string | undefined {
  const m = /^\s*\d+(?:\.\d+)?\s*[;,]\s*(?:url\s*=\s*)?['"]?([^'"\s]+)['"]?/i.exec(value);
  return m?.[1];
}

function decodeBody(buf: Buffer, contentType: string): string {
  const charset = /charset=([\w-]+)/i.exec(contentType)?.[1]?.toLowerCase();
  try {
    return new TextDecoder(charset ?? 'utf-8', { fatal: false }).decode(buf);
  } catch {
    return new TextDecoder('utf-8').decode(buf);
  }
}

/**
 * Fetches a URL following redirects manually. Every hop is re-validated against the SSRF
 * policy before connecting, and DNS answers are validated at socket-connect time.
 */
export async function safeFetch(inputUrl: string, opts: SafeFetchOptions): Promise<FetchResult> {
  const started = Date.now();
  const hops: RedirectHop[] = [];
  const seen = new Set<string>();
  let current = validateTargetUrl(inputUrl, opts.policy);
  const requestedUrl = current.url.href;

  for (let hopNo = 0; ; hopNo++) {
    const guarded = createGuardedLookup(current.fixtureAllowed);
    const agent = new Agent({
      connect: { lookup: guarded.lookup as never, timeout: opts.timeoutMs },
      headersTimeout: opts.timeoutMs,
      bodyTimeout: opts.timeoutMs,
      maxResponseSize: -1,
    });
    try {
      const res = await request(current.url, {
        method: 'GET',
        headers: opts.context.headers,
        dispatcher: agent,
        signal: AbortSignal.timeout(opts.timeoutMs),
        // undici's request() never follows redirects on its own; hops are handled manually below.
      });

      const headers = pickHeaders(res.headers);
      const resolvedIp = guarded.resolved.get(current.hostname) ?? (current.hostname.match(/^[\d.:a-f]+$/i) ? current.hostname : undefined);
      seen.add(current.url.href);

      let nextLocation: string | undefined;
      let kind: RedirectHop['kind'] = 'http';
      if (REDIRECT_STATUSES.has(res.statusCode) && headers.location) {
        nextLocation = headers.location;
      } else if (headers.refresh) {
        const target = parseRefreshValue(headers.refresh);
        if (target) {
          nextLocation = target;
          kind = 'refresh_header';
        }
      }

      if (nextLocation !== undefined) {
        await res.body.dump().catch(() => undefined);
        hops.push({ hop: hopNo, url: current.url.href, status: res.statusCode, location: nextLocation, resolved_ip: resolvedIp, headers, kind });
        let nextUrl: URL;
        try {
          nextUrl = new URL(nextLocation, current.url);
        } catch {
          throw new GeoShieldError('FETCH_FAILED', `Hop ${hopNo} returned an unparseable redirect location.`, { hops });
        }
        if (seen.has(nextUrl.href)) {
          return finish(requestedUrl, current.url.href, res.statusCode, headers, '', 0, false, hops, started, 'redirect_loop');
        }
        if (hops.length >= opts.maxRedirects) {
          return finish(requestedUrl, nextUrl.href, res.statusCode, headers, '', 0, false, hops, started, 'too_many_redirects');
        }
        try {
          current = validateTargetUrl(nextUrl, opts.policy);
        } catch (err) {
          const e = toGeoShieldError(err);
          throw new GeoShieldError(e.code, `Redirect hop ${hopNo + 1} was blocked: ${e.message}`, { hops, blocked_url: nextUrl.href });
        }
        continue;
      }

      hops.push({ hop: hopNo, url: current.url.href, status: res.statusCode, resolved_ip: resolvedIp, headers, kind: 'http' });
      let body = '';
      let bytes = 0;
      let truncated = false;
      if (opts.readBody !== false) {
        const chunks: Buffer[] = [];
        for await (const chunk of res.body) {
          const buf = chunk as Buffer;
          if (bytes + buf.length > opts.maxBodyBytes) {
            chunks.push(buf.subarray(0, opts.maxBodyBytes - bytes));
            bytes = opts.maxBodyBytes;
            truncated = true;
            res.body.destroy();
            break;
          }
          chunks.push(buf);
          bytes += buf.length;
        }
        body = decodeBody(Buffer.concat(chunks), headers['content-type'] ?? '');
      } else {
        await res.body.dump().catch(() => undefined);
      }
      return finish(requestedUrl, current.url.href, res.statusCode, headers, body, bytes, truncated, hops, started);
    } catch (err) {
      throw toGeoShieldError(err);
    } finally {
      agent.close().catch(() => undefined);
    }
  }
}

function finish(
  requested: string,
  finalUrl: string,
  status: number,
  headers: Record<string, string>,
  body: string,
  bytes: number,
  truncated: boolean,
  hops: RedirectHop[],
  started: number,
  chainError?: FetchResult['chain_error'],
): FetchResult {
  return {
    requested_url: requested,
    final_url: finalUrl,
    status,
    headers,
    content_type: headers['content-type'] ?? '',
    body,
    body_bytes: bytes,
    truncated,
    hops,
    ...(chainError ? { chain_error: chainError } : {}),
    elapsed_ms: Date.now() - started,
  };
}
