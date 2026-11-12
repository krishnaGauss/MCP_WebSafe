import type { CheerioAPI } from 'cheerio';
import type { Element } from 'domhandler';

/**
 * Static visibility analysis. Without a browser we cannot compute layout, so this works from
 * inline styles, simple <style> rules and HTML attributes. It recognises the common hiding
 * techniques used for SEO spam and hidden AI instructions, and the common legitimate patterns
 * (screen-reader text, menus, accordions, tabs, modals, tooltips).
 */

export type Declarations = Record<string, string>;

export interface Visibility {
  hidden: boolean;
  /** Reasons on this element itself (empty when hidden only through an ancestor). */
  reasons: string[];
  /** The element that introduces the hiding (itself or an ancestor). */
  hiddenBy?: Element;
  /** Text is visible but rendered so small it is effectively unreadable. */
  tiny: boolean;
  /** Legitimate hiding pattern recognised on this element or an ancestor. */
  legitimate?: string;
}

const SKIP_TAGS = new Set(['script', 'style', 'noscript', 'template', 'head', 'meta', 'link', 'title', 'base']);
const LEGIT_WORDS = new Set([
  'menu', 'submenu', 'megamenu', 'nav', 'navbar', 'navigation', 'dropdown', 'drop', 'accordion', 'collapse', 'collapsible', 'collapsed',
  'modal', 'dialog', 'popup', 'popover', 'tooltip', 'tab', 'tabs', 'tabpane', 'tabpanel', 'drawer', 'offcanvas', 'faq', 'cookie',
  'cookies', 'consent', 'toast', 'lightbox', 'carousel', 'slide', 'slider', 'hamburger', 'flyout', 'overlay', 'expander', 'disclosure',
  'skip', 'search',
]);

/** Splits class/id strings into lowercase words, including camelCase and CSS-in-JS names (LanguageDropdown-styles__x). */
function classWords(cls: string): string[] {
  return cls
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[\s_-]+/)
    .map((w) => w.toLowerCase())
    .filter(Boolean);
}
const LEGIT_ROLES = new Set(['tab', 'tabpanel', 'dialog', 'alertdialog', 'menu', 'menubar', 'menuitem', 'tooltip', 'navigation', 'listbox', 'region']);
const LEGIT_TAGS = new Set(['details', 'dialog', 'nav', 'menu', 'select', 'option']);

const NAMED_COLORS: Record<string, string> = {
  white: '255,255,255', black: '0,0,0', red: '255,0,0', green: '0,128,0', blue: '0,0,255',
  yellow: '255,255,0', gray: '128,128,128', grey: '128,128,128', silver: '192,192,192', transparent: 'transparent',
  whitesmoke: '245,245,245', snow: '255,250,250', ivory: '255,255,240', ghostwhite: '248,248,255',
};

export function parseDeclarations(css: string): Declarations {
  const out: Declarations = {};
  for (const part of css.split(';')) {
    const idx = part.indexOf(':');
    if (idx < 0) continue;
    const prop = part.slice(0, idx).trim().toLowerCase();
    const value = part.slice(idx + 1).replace(/!important/i, '').trim().toLowerCase();
    if (prop && value) out[prop] = value;
  }
  return out;
}

/** Remove comments and nested at-rule blocks (@media, @supports, @keyframes...) from a stylesheet. */
function stripAtRules(css: string): string {
  let out = '';
  let i = 0;
  css = css.replace(/\/\*[\s\S]*?\*\//g, '');
  while (i < css.length) {
    if (css[i] === '@') {
      const brace = css.indexOf('{', i);
      const semi = css.indexOf(';', i);
      if (semi !== -1 && (brace === -1 || semi < brace)) {
        i = semi + 1;
        continue;
      }
      if (brace === -1) break;
      let depth = 0;
      let j = brace;
      for (; j < css.length; j++) {
        if (css[j] === '{') depth++;
        else if (css[j] === '}' && --depth === 0) break;
      }
      i = j + 1;
      continue;
    }
    out += css[i];
    i++;
  }
  return out;
}

/** Applies simple <style> rules to matching elements. Pseudo-class selectors are ignored. */
export function computeSheetStyles($: CheerioAPI): Map<Element, Declarations> {
  const styles = new Map<Element, Declarations>();
  $('style').each((_, el) => {
    const css = stripAtRules($(el).text());
    const ruleRe = /([^{}]+)\{([^{}]*)\}/g;
    let m: RegExpExecArray | null;
    while ((m = ruleRe.exec(css))) {
      const decls = parseDeclarations(m[2] ?? '');
      if (Object.keys(decls).length === 0) continue;
      for (const raw of (m[1] ?? '').split(',')) {
        const sel = raw.trim();
        if (!sel || sel.includes(':') || sel.length > 200) continue;
        try {
          $(sel).each((__, target) => {
            if (target.type !== 'tag') return;
            styles.set(target, { ...(styles.get(target) ?? {}), ...decls });
          });
        } catch {
          /* unsupported selector */
        }
      }
    }
  });
  return styles;
}

function pxValue(v: string | undefined): number | undefined {
  if (!v) return undefined;
  const m = /^(-?\d*\.?\d+)(px|pt|em|rem|%|vw|vh)?$/.exec(v.trim());
  if (!m) return undefined;
  const n = Number(m[1]);
  switch (m[2]) {
    case 'pt': return n * 1.333;
    case 'em': case 'rem': return n * 16;
    case '%': case 'vw': case 'vh': return n === 0 ? 0 : undefined;
    default: return n;
  }
}

export function normalizeColor(v: string | undefined): string | undefined {
  if (!v) return undefined;
  const s = v.trim().toLowerCase();
  if (NAMED_COLORS[s]) return NAMED_COLORS[s];
  let m = /^#([0-9a-f]{3})$/.exec(s);
  if (m) return m[1]!.split('').map((c) => parseInt(c + c, 16)).join(',');
  m = /^#([0-9a-f]{6})([0-9a-f]{2})?$/.exec(s);
  if (m) return [0, 2, 4].map((i) => parseInt(m![1]!.slice(i, i + 2), 16)).join(',');
  m = /^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)(?:[\s,/]+([\d.]+%?))?\s*\)$/.exec(s);
  if (m) {
    if (m[4] !== undefined && parseFloat(m[4]) === 0) return 'transparent';
    return `${m[1]},${m[2]},${m[3]}`;
  }
  return undefined;
}

function colorsClose(a: string, b: string): boolean {
  if (a === 'transparent' || b === 'transparent') return false;
  const pa = a.split(',').map(Number);
  const pb = b.split(',').map(Number);
  const dist = Math.sqrt(pa.reduce((acc, v, i) => acc + (v - (pb[i] ?? 0)) ** 2, 0));
  return dist < 24;
}

/** Effective background beneath an element. `image` means a background image/gradient whose colour cannot be known statically. */
export interface Background {
  color: string;
  declared: boolean;
  image: boolean;
}

/** Prefix for colour matches that static analysis cannot confirm (no declared background, or an image/video nearby). */
export const WEAK_COLOUR_REASON = 'text colour matches background (unconfirmed)';

function backgroundOf(style: Declarations, inherited: Background): Background {
  const shorthand = style.background ?? '';
  if (/url\(|gradient\(/.test(shorthand) || (style['background-image'] && style['background-image'] !== 'none')) {
    return { color: inherited.color, declared: true, image: true };
  }
  const own = normalizeColor(style['background-color'] ?? shorthand.split(/\s+/)[0]);
  if (own && own !== 'transparent') return { color: own, declared: true, image: false };
  return inherited;
}

function ownHidingReasons(el: Element, style: Declarations): string[] {
  const reasons: string[] = [];
  if (el.attribs.hidden !== undefined) reasons.push('hidden attribute');
  if (el.name === 'input' && (el.attribs.type ?? '').toLowerCase() === 'hidden') reasons.push('input type=hidden');
  if (style.display === 'none') reasons.push('display:none');
  if (style.visibility === 'hidden' || style.visibility === 'collapse') reasons.push(`visibility:${style.visibility}`);
  const opacity = style.opacity !== undefined ? Number(style.opacity) : undefined;
  if (opacity !== undefined && Number.isFinite(opacity) && opacity <= 0.05) reasons.push(`opacity:${style.opacity}`);
  const fs = pxValue(style['font-size']);
  if (fs !== undefined && fs <= 1) reasons.push(`font-size:${style['font-size']}`);
  const pos = style.position;
  if (pos === 'absolute' || pos === 'fixed') {
    for (const side of ['left', 'top', 'right']) {
      const v = pxValue(style[side]);
      if (v !== undefined && v <= -500) reasons.push(`off-screen (${side}:${style[side]})`);
    }
  }
  const indent = pxValue(style['text-indent']);
  if (indent !== undefined && indent <= -500) reasons.push(`off-screen (text-indent:${style['text-indent']})`);
  const w = pxValue(style.width);
  const h = pxValue(style.height);
  if (((w !== undefined && w <= 1) || (h !== undefined && h <= 1)) && (style.overflow === 'hidden' || style.clip || style['clip-path'])) {
    reasons.push(`zero-size box (${w !== undefined ? `width:${style.width}` : `height:${style.height}`}, overflow hidden)`);
  }
  if (style.clip && /rect\(\s*0/.test(style.clip)) reasons.push(`clip:${style.clip}`);
  if (style['clip-path'] && /inset\(\s*(50%|100%)/.test(style['clip-path'])) reasons.push(`clip-path:${style['clip-path']}`);
  if (style.transform && /scale\(\s*0(\.0+)?\s*[,)]/.test(style.transform)) reasons.push(`transform:${style.transform}`);
  return reasons;
}

/**
 * Same-colour text check. Colour is inherited, so this is evaluated on elements that directly contain text,
 * using the colour their text actually inherits (a wrapper declaring color:#fff whose children set their own
 * colour is not hidden).
 */
function colourReason(el: Element, color: string | undefined, bg: Background, nearMedia: boolean): string | undefined {
  if (!color || bg.image || !colorsClose(color, bg.color)) return undefined;
  const hasOwnText = el.children.some((c) => c.type === 'text' && (c as unknown as { data: string }).data.trim().length > 0);
  if (!hasOwnText) return undefined;
  // Without a declared background the text may sit on an image or on a colour set by an external stylesheet.
  if (!bg.declared) return `${WEAK_COLOUR_REASON}: rgb(${color}) with no background declared on any ancestor`;
  if (nearMedia) return `${WEAK_COLOUR_REASON}: rgb(${color}) on rgb(${bg.color}), but an image/video is nearby and the text may overlay it`;
  return `text colour matches background (rgb(${color}) on rgb(${bg.color}))`;
}

function legitimacyOf(el: Element, style: Declarations): string | undefined {
  const cls = `${el.attribs.class ?? ''} ${el.attribs.id ?? ''}`;
  if (/(sr-only|visually-hidden|screen-reader|screenreader|a11y|assistive)/i.test(cls)) return 'screen-reader-only text pattern';
  // Classic sr-only CSS: absolute, 1px box, clipped.
  if ((style.position === 'absolute') && (style.clip || style['clip-path']) && (pxValue(style.width) ?? 99) <= 1) return 'screen-reader-only CSS pattern';
  if (LEGIT_TAGS.has(el.name)) return `<${el.name}> element (interactive disclosure/navigation)`;
  const role = (el.attribs.role ?? '').toLowerCase();
  if (LEGIT_ROLES.has(role)) return `role="${role}"`;
  if (el.attribs['aria-modal'] === 'true') return 'aria-modal dialog';
  const word = classWords(cls).find((w) => LEGIT_WORDS.has(w));
  if (word) return `UI component class/id containing "${word}"`;
  if (el.name === 'input') return 'hidden form input';
  return undefined;
}

/**
 * Walks the DOM once and returns a visibility record for every element.
 */
export function computeVisibility($: CheerioAPI): Map<Element, Visibility> {
  const sheet = computeSheetStyles($);
  const result = new Map<Element, Visibility>();
  const controlledIds = new Set<string>();
  $('[aria-controls]').each((_, el) => {
    for (const id of ((el as Element).attribs['aria-controls'] ?? '').split(/\s+/)) if (id) controlledIds.add(id);
  });

  const styleOf = (el: Element): Declarations => ({ ...(sheet.get(el) ?? {}), ...parseDeclarations(el.attribs.style ?? '') });

  // Containers (up to 3 levels above) of images/video: text inside them may be overlaid on media (cards, heroes).
  const mediaContainers = new Set<Element>();
  $('img, picture, video, canvas').each((_, m) => {
    let node = (m as Element).parent as Element | null;
    for (let i = 0; i < 3 && node && node.type === 'tag'; i++, node = node.parent as Element | null) mediaContainers.add(node);
  });

  const walk = (el: Element, parent: Visibility | undefined, parentBg: Background, parentLegit: string | undefined, parentMedia: number, parentColor: string): void => {
    if (SKIP_TAGS.has(el.name)) return;
    const style = styleOf(el);
    const mediaDepth = mediaContainers.has(el) ? 4 : Math.max(0, parentMedia - 1);
    const bg = backgroundOf(style, parentBg);
    const ownColor = normalizeColor(style.color);
    const color = ownColor && ownColor !== 'transparent' ? ownColor : parentColor;
    const reasons = ownHidingReasons(el, style);
    const colour = colourReason(el, color, bg, mediaDepth > 0);
    if (colour) reasons.push(colour);
    let legit = parentLegit ?? legitimacyOf(el, style);
    if (!legit && el.attribs.id && controlledIds.has(el.attribs.id)) legit = 'toggled by an aria-controls element';
    const fs = pxValue(style['font-size']);
    const tiny = (fs !== undefined && fs > 1 && fs <= 3) || (parent?.tiny ?? false);
    const hidden = (parent?.hidden ?? false) || reasons.length > 0;
    const vis: Visibility = {
      hidden,
      reasons,
      tiny,
      ...(hidden ? { hiddenBy: parent?.hidden ? parent.hiddenBy : el } : {}),
      ...(legit ? { legitimate: legit } : {}),
    };
    result.set(el, vis);
    for (const child of el.children) {
      if (child.type === 'tag' || child.type === 'script' || child.type === 'style') walk(child as Element, vis, bg, legit, mediaDepth, color);
    }
  };

  // Browsers default to a white canvas; <html>/<body> backgrounds are picked up by the walk itself.
  const canvas: Background = { color: '255,255,255', declared: false, image: false };
  for (const top of $.root().children().toArray()) {
    if (top.type === 'tag') walk(top as Element, undefined, canvas, undefined, 0, '0,0,0');
  }
  return result;
}
