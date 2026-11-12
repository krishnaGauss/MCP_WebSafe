import { createHash } from 'node:crypto';
import * as cheerio from 'cheerio';
import type { CheerioAPI } from 'cheerio';
import type { AnyNode, Element } from 'domhandler';
import { computeVisibility, type Visibility } from './visibility.js';
import { hostnameOf, isCrossSite, isHttpUrl, registrableDomain, resolveUrl } from './url-utils.js';

export interface LinkInfo {
  href: string;
  raw_href: string;
  text: string;
  title?: string;
  rel: string;
  selector: string;
  hidden: boolean;
  hidden_reason?: string;
  legitimate_hidden?: string;
  tiny: boolean;
  external: boolean;
  domain?: string;
  is_http: boolean;
}

export interface ScriptInfo {
  selector: string;
  src?: string;
  host?: string;
  external: boolean;
  /** Inline script body (kept in memory for analysis only; never persisted in full). */
  inline?: string;
}

export interface IframeInfo {
  selector: string;
  src: string;
  host?: string;
  external: boolean;
  hidden: boolean;
  hidden_reason?: string;
  width?: string;
  height?: string;
}

export interface AttributeText {
  selector: string;
  attribute: string;
  value: string;
  hidden: boolean;
}

export interface HiddenElement {
  selector: string;
  tag: string;
  reasons: string[];
  text: string;
  legitimate?: string;
  links: string[];
}

export interface PageSnapshot {
  url: string;
  domain?: string;
  title?: string;
  meta_description?: string;
  canonical?: string;
  meta: Array<{ key: string; content: string; selector: string }>;
  meta_refresh: Array<{ content: string; selector: string }>;
  json_ld: Array<{ selector: string; raw: string; parsed?: unknown; error?: string }>;
  comments: Array<{ location: string; text: string }>;
  links: LinkInfo[];
  scripts: ScriptInfo[];
  iframes: IframeInfo[];
  attributes: AttributeText[];
  hidden_elements: HiddenElement[];
  visible_text: string;
  page_hash: string;
  text_fingerprint: string;
}

const collapse = (s: string): string => s.replace(/\s+/g, ' ').trim();

const NON_TEXT_TAGS = new Set(['script', 'style', 'noscript', 'template']);

/** Human-readable text of an element, excluding <script>/<style>/<noscript>/<template> contents (unlike cheerio's .text()). */
export function textOf(node: AnyNode): string {
  if (node.type === 'text') return (node as unknown as { data: string }).data;
  if (node.type === 'script' || node.type === 'style') return '';
  if (node.type === 'tag' && NON_TEXT_TAGS.has((node as Element).name)) return '';
  const children = (node as unknown as { children?: AnyNode[] }).children;
  if (!children) return '';
  // Separate block-level siblings so "Headline" + "Summary" do not run together.
  return children.map((c) => textOf(c)).join(node.type === 'tag' && (node as Element).name !== 'a' ? ' ' : '');
}

export function selectorPath($: CheerioAPI, el: Element): string {
  const parts: string[] = [];
  let node: Element | null = el;
  while (node && node.type === 'tag' && parts.length < 7) {
    const id = node.attribs.id;
    if (id && /^[A-Za-z][\w-]*$/.test(id)) {
      parts.unshift(`${node.name}#${id}`);
      break;
    }
    let part = node.name;
    const cls = (node.attribs.class ?? '').trim().split(/\s+/)[0];
    if (cls && /^[A-Za-z_][\w-]*$/.test(cls)) part += `.${cls}`;
    const parent = node.parent as Element | null;
    if (parent && parent.type === 'tag') {
      const same = parent.children.filter((c) => c.type === 'tag' && (c as Element).name === node!.name);
      if (same.length > 1) part += `:nth-of-type(${same.indexOf(node) + 1})`;
    }
    parts.unshift(part);
    if (node.name === 'body' || node.name === 'head') break;
    node = parent && parent.type === 'tag' ? parent : null;
  }
  return parts.join(' > ');
}

function hiddenReason(vis: Visibility | undefined, $: CheerioAPI): string | undefined {
  if (!vis?.hidden) return undefined;
  if (vis.reasons.length) return vis.reasons.join('; ');
  const by = vis.hiddenBy;
  return by ? `inside hidden ancestor ${selectorPath($, by)}` : 'hidden';
}

export function parseHtml(html: string, pageUrl: string): PageSnapshot {
  const $ = cheerio.load(html);
  const vis = computeVisibility($);
  const baseHref = $('base[href]').attr('href');
  const base = (baseHref && resolveUrl(baseHref, pageUrl)?.href) || pageUrl;
  const pageDomain = registrableDomain(pageUrl);

  const meta: PageSnapshot['meta'] = [];
  const metaRefresh: PageSnapshot['meta_refresh'] = [];
  $('meta').each((_, el) => {
    const e = el as Element;
    const key = e.attribs.name ?? e.attribs.property ?? e.attribs.itemprop ?? e.attribs['http-equiv'];
    const content = e.attribs.content;
    if (!key || content === undefined) return;
    if ((e.attribs['http-equiv'] ?? '').toLowerCase() === 'refresh') metaRefresh.push({ content, selector: selectorPath($, e) });
    meta.push({ key: key.toLowerCase(), content, selector: selectorPath($, e) });
  });

  const canonicalHref = $('link[rel~="canonical"]').attr('href');
  const canonical = canonicalHref ? resolveUrl(canonicalHref, base)?.href : undefined;

  const jsonLd: PageSnapshot['json_ld'] = [];
  $('script[type="application/ld+json"]').each((_, el) => {
    const raw = $(el).text();
    const entry: PageSnapshot['json_ld'][number] = { selector: selectorPath($, el as Element), raw };
    try {
      entry.parsed = JSON.parse(raw);
    } catch (err) {
      entry.error = (err as Error).message;
    }
    jsonLd.push(entry);
  });

  const comments: PageSnapshot['comments'] = [];
  const walkComments = (node: AnyNode, parentSel: string): void => {
    if (node.type === 'comment') {
      const text = collapse((node as unknown as { data: string }).data ?? '');
      if (text) comments.push({ location: `HTML comment in ${parentSel || 'document'}`, text });
      return;
    }
    const children = (node as unknown as { children?: AnyNode[] }).children;
    if (!children) return;
    const sel = node.type === 'tag' ? selectorPath($, node as Element) : parentSel;
    for (const c of children) walkComments(c, sel);
  };
  walkComments($.root()[0] as AnyNode, '');

  const links: LinkInfo[] = [];
  $('a[href], area[href]').each((_, el) => {
    const e = el as Element;
    const raw = e.attribs.href ?? '';
    const resolved = resolveUrl(raw, base);
    const v = vis.get(e);
    const isHttp = isHttpUrl(resolved);
    const href = resolved?.href ?? raw;
    links.push({
      href,
      raw_href: raw,
      text: collapse(textOf(e) || e.attribs['aria-label'] || $(e).find('img').attr('alt') || ''),
      ...(e.attribs.title ? { title: e.attribs.title } : {}),
      rel: (e.attribs.rel ?? '').toLowerCase(),
      selector: selectorPath($, e),
      hidden: v?.hidden ?? false,
      ...(v?.hidden ? { hidden_reason: hiddenReason(v, $) } : {}),
      ...(v?.legitimate ? { legitimate_hidden: v.legitimate } : {}),
      tiny: v?.tiny ?? false,
      external: isHttp ? isCrossSite(href, pageUrl) : false,
      ...(isHttp ? { domain: registrableDomain(href) } : {}),
      is_http: isHttp,
    });
  });

  const scripts: ScriptInfo[] = [];
  $('script').each((_, el) => {
    const e = el as Element;
    const type = (e.attribs.type ?? '').toLowerCase();
    if (type && !/javascript|module|ecmascript/.test(type)) return;
    const src = e.attribs.src ? resolveUrl(e.attribs.src, base)?.href : undefined;
    scripts.push({
      selector: selectorPath($, e),
      ...(src ? { src, host: hostnameOf(src), external: isCrossSite(src, pageUrl) } : { external: false, inline: $(e).text() }),
    });
  });

  const iframes: IframeInfo[] = [];
  $('iframe[src], frame[src], embed[src], object[data]').each((_, el) => {
    const e = el as Element;
    const rawSrc = e.attribs.src ?? e.attribs.data ?? '';
    const src = resolveUrl(rawSrc, base)?.href ?? rawSrc;
    const v = vis.get(e);
    const w = e.attribs.width;
    const h = e.attribs.height;
    const zeroAttr = (w !== undefined && Number.parseFloat(w) <= 1) || (h !== undefined && Number.parseFloat(h) <= 1);
    const reason = hiddenReason(v, $) ?? (zeroAttr ? `width=${w ?? '?'} height=${h ?? '?'}` : undefined);
    iframes.push({
      selector: selectorPath($, e),
      src,
      host: hostnameOf(src),
      external: isCrossSite(src, pageUrl),
      hidden: (v?.hidden ?? false) || zeroAttr,
      ...(reason ? { hidden_reason: reason } : {}),
      ...(w ? { width: w } : {}),
      ...(h ? { height: h } : {}),
    });
  });

  const attributes: AttributeText[] = [];
  $('[alt], [aria-label], [title], [aria-description], [data-ai], [data-llm], [data-prompt]').each((_, el) => {
    const e = el as Element;
    for (const attribute of ['alt', 'aria-label', 'title', 'aria-description', 'data-ai', 'data-llm', 'data-prompt']) {
      const value = e.attribs[attribute];
      if (value && value.trim().length > 0) {
        attributes.push({ selector: selectorPath($, e), attribute, value: collapse(value), hidden: vis.get(e)?.hidden ?? false });
      }
    }
  });

  const hiddenElements: HiddenElement[] = [];
  const visibleParts: string[] = [];
  for (const [el, v] of vis) {
    if (v.hidden && v.hiddenBy === el) {
      const text = collapse(textOf(el)).slice(0, 4000);
      const elLinks = $(el)
        .find('a[href]')
        .toArray()
        .map((a) => resolveUrl((a as Element).attribs.href ?? '', base)?.href)
        .filter((x): x is string => !!x);
      if (el.name === 'a' && el.attribs.href) {
        const self = resolveUrl(el.attribs.href, base)?.href;
        if (self) elLinks.unshift(self);
      }
      hiddenElements.push({
        selector: selectorPath($, el),
        tag: el.name,
        reasons: v.reasons,
        text,
        ...(v.legitimate ? { legitimate: v.legitimate } : {}),
        links: elLinks,
      });
    }
    if (!v.hidden) {
      for (const child of el.children) {
        if (child.type === 'text') visibleParts.push((child as unknown as { data: string }).data);
      }
    }
  }
  const visibleText = collapse(visibleParts.join(' '));

  const title = collapse($('head > title').first().text() || $('title').first().text()) || undefined;
  const description = meta.find((m) => m.key === 'description')?.content;

  return {
    url: pageUrl,
    ...(pageDomain ? { domain: pageDomain } : {}),
    ...(title ? { title } : {}),
    ...(description ? { meta_description: collapse(description) } : {}),
    ...(canonical ? { canonical } : {}),
    meta,
    meta_refresh: metaRefresh,
    json_ld: jsonLd,
    comments,
    links,
    scripts,
    iframes,
    attributes,
    hidden_elements: hiddenElements,
    visible_text: visibleText,
    page_hash: createHash('sha256').update(html).digest('hex'),
    text_fingerprint: createHash('sha256').update(visibleText.toLowerCase()).digest('hex'),
  };
}
