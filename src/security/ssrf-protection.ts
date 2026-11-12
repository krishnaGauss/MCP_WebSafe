import dns from 'node:dns';
import net from 'node:net';
import ipaddr from 'ipaddr.js';
import type { SecurityPolicy } from '../config.js';
import { GeoShieldError } from '../errors.js';

/** Hostnames that must never be fetched regardless of what they resolve to. */
const BLOCKED_HOSTNAMES = [/^localhost$/i, /\.localhost$/i, /^metadata(\.google)?\.internal$/i, /\.internal$/i, /\.local$/i, /^metadata$/i, /^instance-data$/i];

export interface ValidatedTarget {
  url: URL;
  hostname: string;
  port: number;
  /** True only when the host:port is explicitly listed in the test fixture allowlist. */
  fixtureAllowed: boolean;
}

function defaultPort(url: URL): number {
  if (url.port) return Number(url.port);
  return url.protocol === 'https:' ? 443 : 80;
}

function stripBrackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/**
 * Classify an IP address. Only globally routable unicast addresses are allowed.
 * IPv4-mapped / translated IPv6 forms are unwrapped and checked as IPv4.
 */
export function isPublicIp(address: string): boolean {
  if (!ipaddr.isValid(address)) return false;
  let ip = ipaddr.parse(address);
  if (ip.kind() === 'ipv6') {
    const v6 = ip as ipaddr.IPv6;
    if (v6.isIPv4MappedAddress()) ip = v6.toIPv4Address();
    else if (v6.range() !== 'unicast') return false;
  }
  if (ip.kind() === 'ipv4') {
    const v4 = ip as ipaddr.IPv4;
    if (v4.range() !== 'unicast') return false;
    // Ranges ipaddr.js labels unicast but that are not safe external destinations.
    const extra: Array<[string, number]> = [
      ['0.0.0.0', 8], // "this network"
      ['192.0.0.0', 24], // IETF protocol assignments
      ['198.18.0.0', 15], // benchmarking
      ['100.64.0.0', 10], // carrier-grade NAT (Alibaba metadata 100.100.100.200)
    ];
    for (const [range, bits] of extra) {
      if (v4.match(ipaddr.parse(range) as ipaddr.IPv4, bits)) return false;
    }
  }
  return true;
}

/**
 * Stage-1 validation: protocol, credentials, hostname, port and IP-literal checks.
 * DNS-resolved addresses are checked separately at connect time by {@link createGuardedLookup},
 * so the address that is validated is the address that is connected to (no rebinding window).
 */
export function validateTargetUrl(input: string | URL, policy: SecurityPolicy): ValidatedTarget {
  let url: URL;
  try {
    url = typeof input === 'string' ? new URL(input.trim()) : new URL(input.href);
  } catch {
    throw new GeoShieldError('INVALID_URL', 'The URL could not be parsed. Provide an absolute http(s) URL.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new GeoShieldError('BLOCKED_DESTINATION', `Protocol "${url.protocol}" is not allowed; only http and https can be scanned.`);
  }
  if (url.username || url.password) {
    throw new GeoShieldError('BLOCKED_DESTINATION', 'URLs containing embedded credentials are not allowed.');
  }
  const hostname = stripBrackets(url.hostname).toLowerCase();
  if (!hostname) throw new GeoShieldError('INVALID_URL', 'The URL has no hostname.');
  const port = defaultPort(url);
  const fixtureAllowed = policy.fixtureAllow.has(`${hostname}:${port}`);

  if (!fixtureAllowed) {
    if (BLOCKED_HOSTNAMES.some((re) => re.test(hostname))) {
      throw new GeoShieldError('BLOCKED_DESTINATION', `Hostname "${hostname}" refers to a local or internal service and cannot be scanned.`);
    }
    if (!policy.allowedPorts.has(port)) {
      throw new GeoShieldError('BLOCKED_DESTINATION', `Port ${port} is not in the allowed port list (${[...policy.allowedPorts].join(', ')}).`);
    }
    // WHATWG URL already normalises decimal/octal/hex IPv4 forms (e.g. http://2130706433 -> 127.0.0.1).
    if (net.isIP(hostname) && !isPublicIp(hostname)) {
      throw new GeoShieldError('BLOCKED_DESTINATION', `Address ${hostname} is private, loopback, link-local or otherwise non-public and cannot be scanned.`);
    }
    if (!net.isIP(hostname) && !hostname.includes('.')) {
      throw new GeoShieldError('BLOCKED_DESTINATION', `Single-label hostname "${hostname}" is treated as internal and cannot be scanned.`);
    }
  }
  return { url, hostname, port, fixtureAllowed };
}

type LookupAddress = { address: string; family: number };
type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

export interface GuardedLookup {
  lookup: (hostname: string, options: dns.LookupOptions, callback: LookupCallback) => void;
  /** Addresses actually handed to the socket, keyed by hostname. */
  resolved: Map<string, string>;
}

/**
 * A dns.lookup replacement handed to the HTTP client's socket connector.
 * Every resolved address must be public (unless the target is fixture-allowlisted),
 * which defeats DNS rebinding: validation and connection use the same answer.
 */
export function createGuardedLookup(allowNonPublic: boolean, resolver: typeof dns.lookup = dns.lookup): GuardedLookup {
  const resolved = new Map<string, string>();
  const lookup = (hostname: string, options: dns.LookupOptions, callback: LookupCallback): void => {
    resolver(hostname, { all: true, family: options?.family ?? 0 }, (err, addresses) => {
      if (err) return callback(err, []);
      const list = (addresses as unknown as LookupAddress[]) ?? [];
      if (list.length === 0) {
        const e: NodeJS.ErrnoException = new Error(`No addresses for ${hostname}`);
        e.code = 'ENOTFOUND';
        return callback(e, []);
      }
      if (!allowNonPublic) {
        const bad = list.find((a) => !isPublicIp(a.address));
        if (bad) {
          const e = new GeoShieldError('BLOCKED_DESTINATION', `Hostname "${hostname}" resolves to non-public address ${bad.address}; request blocked to prevent SSRF.`);
          return callback(e as unknown as NodeJS.ErrnoException, []);
        }
      }
      const first = list[0]!;
      resolved.set(hostname, first.address);
      if (options?.all) return callback(null, list);
      return callback(null, first.address, first.family);
    });
  };
  return { lookup, resolved };
}
