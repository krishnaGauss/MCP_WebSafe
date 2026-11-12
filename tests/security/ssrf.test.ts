import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GeoShieldError } from '../../src/errors.js';
import { createGuardedLookup, isPublicIp, validateTargetUrl } from '../../src/security/ssrf-protection.js';
import { REQUEST_CONTEXT_PRESETS } from '../../src/scanner/request-contexts.js';
import { safeFetch } from '../../src/scanner/safe-fetch.js';
import { startFixtureSite, type FixtureSite } from '../fixtures/site.js';
import { testConfig } from '../helpers/env.js';

const policy = testConfig().security;

function blocked(url: string): string {
  try {
    validateTargetUrl(url, policy);
  } catch (err) {
    expect(err).toBeInstanceOf(GeoShieldError);
    return (err as GeoShieldError).code;
  }
  return 'ALLOWED';
}

describe('validateTargetUrl', () => {
  it.each([
    'http://127.0.0.1/',
    'http://localhost/',
    'http://foo.localhost/',
    'http://10.1.2.3/',
    'http://172.16.0.1/',
    'http://192.168.1.1/',
    'http://169.254.169.254/latest/meta-data/',
    'http://100.100.100.200/',
    'http://0.0.0.0/',
    'http://[::1]/',
    'http://[fd00:ec2::254]/',
    'http://[fe80::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://[::ffff:a9fe:a9fe]/',
    'http://2130706433/', // decimal 127.0.0.1
    'http://0x7f000001/', // hex 127.0.0.1
    'http://0177.0.0.1/', // octal
    'http://metadata.google.internal/',
    'http://intranet/',
    'http://printer.local/',
  ])('blocks %s', (url) => {
    expect(blocked(url)).toBe('BLOCKED_DESTINATION');
  });

  it.each(['file:///etc/passwd', 'ftp://example.com/', 'gopher://example.com/', 'javascript:alert(1)', 'data:text/html,hi'])('blocks protocol %s', (url) => {
    expect(['BLOCKED_DESTINATION', 'INVALID_URL']).toContain(blocked(url));
  });

  it('blocks credentials and non-standard ports', () => {
    expect(blocked('https://user:pass@example.com/')).toBe('BLOCKED_DESTINATION');
    expect(blocked('http://example.com:6379/')).toBe('BLOCKED_DESTINATION');
  });

  it('rejects garbage', () => {
    expect(blocked('not a url')).toBe('INVALID_URL');
  });

  it('allows public hosts and IPs', () => {
    expect(blocked('https://example.com/path?x=1')).toBe('ALLOWED');
    expect(blocked('http://93.184.215.14/')).toBe('ALLOWED');
  });

  it('fixture allowlist only opens the exact host:port', () => {
    const p = { ...policy, fixtureAllow: new Set(['127.0.0.1:4599']) };
    expect(() => validateTargetUrl('http://127.0.0.1:4599/x', p)).not.toThrow();
    expect(() => validateTargetUrl('http://127.0.0.1:4600/x', p)).toThrow(GeoShieldError);
    expect(() => validateTargetUrl('http://127.0.0.1/x', p)).toThrow(GeoShieldError);
  });
});

describe('isPublicIp', () => {
  it('classifies addresses', () => {
    expect(isPublicIp('8.8.8.8')).toBe(true);
    expect(isPublicIp('2606:4700:4700::1111')).toBe(true);
    for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.0.1', '169.254.1.1', '100.64.0.1', '::1', 'fc00::1', '::ffff:10.0.0.1', '224.0.0.1', '198.18.0.1']) {
      expect(isPublicIp(ip), ip).toBe(false);
    }
  });
});

describe('guarded DNS lookup (rebinding defence)', () => {
  const fakeResolver = (answers: Array<{ address: string; family: number }>) =>
    ((_host: string, _opts: unknown, cb: (err: null, addrs: unknown) => void) => cb(null, answers)) as never;

  it('rejects a hostname that resolves to a private address', async () => {
    const { lookup } = createGuardedLookup(false, fakeResolver([{ address: '10.0.0.5', family: 4 }]));
    const err = await new Promise((resolve) => lookup('rebind.example', {}, (e) => resolve(e)));
    expect(err).toBeInstanceOf(GeoShieldError);
    expect((err as GeoShieldError).code).toBe('BLOCKED_DESTINATION');
  });

  it('rejects when ANY returned address is private', async () => {
    const { lookup } = createGuardedLookup(false, fakeResolver([{ address: '93.184.215.14', family: 4 }, { address: '127.0.0.1', family: 4 }]));
    const err = await new Promise((resolve) => lookup('mixed.example', {}, (e) => resolve(e)));
    expect(err).toBeInstanceOf(GeoShieldError);
  });

  it('passes public answers through and records the pinned address', async () => {
    const g = createGuardedLookup(false, fakeResolver([{ address: '93.184.215.14', family: 4 }]));
    const addr = await new Promise((resolve) => g.lookup('ok.example', {}, (_e, a) => resolve(a)));
    expect(addr).toBe('93.184.215.14');
    expect(g.resolved.get('ok.example')).toBe('93.184.215.14');
  });
});

describe('safeFetch redirect revalidation', () => {
  let site: FixtureSite;
  beforeAll(async () => {
    site = await startFixtureSite();
  });
  afterAll(async () => site.close());

  const opts = () => ({
    policy: testConfig(site.allow).security,
    context: REQUEST_CONTEXT_PRESETS.desktop_browser,
    maxRedirects: 10,
    timeoutMs: 5000,
    maxBodyBytes: 100_000,
  });

  it('blocks a redirect into a private network address', async () => {
    await expect(safeFetch(`${site.site}/redirect-to-private`, opts())).rejects.toMatchObject({ code: 'BLOCKED_DESTINATION' });
  });

  it('blocks a redirect to the cloud metadata endpoint and keeps the recorded hops', async () => {
    const err = (await safeFetch(`${site.site}/redirect-to-metadata`, opts()).catch((e) => e)) as GeoShieldError;
    expect(err.code).toBe('BLOCKED_DESTINATION');
    expect((err.details?.hops as unknown[]).length).toBe(1);
  });

  it('truncates oversized bodies instead of reading them fully', async () => {
    const r = await safeFetch(`${site.site}/large`, opts());
    expect(r.truncated).toBe(true);
    expect(r.body_bytes).toBe(100_000);
  });

  it('stops redirect loops', async () => {
    const r = await safeFetch(`${site.site}/loop`, opts());
    expect(r.chain_error).toBe('redirect_loop');
  });

  it('refuses loopback without the fixture allowlist', async () => {
    await expect(safeFetch(`${site.site}/clean`, { ...opts(), policy: testConfig().security })).rejects.toMatchObject({ code: 'BLOCKED_DESTINATION' });
  });
});
