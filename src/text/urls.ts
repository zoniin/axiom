/**
 * URL canonicalization and host matching. All outbound URLs go through
 * `checkUrl`, which is default-deny: anything it cannot positively verify is rejected.
 */

export interface UrlCheck {
  ok: boolean;
  reason?: string;
  url?: URL;
}

const utf8 = new TextDecoder();
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Returns true when `host` matches `pattern`. `*.example.com` matches
 * `a.example.com` and `a.b.example.com` but not `example.com` or `evilexample.com`.
 */
export function hostMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const p = pattern.toLowerCase();
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    return h.length > suffix.length && h.endsWith(suffix);
  }
  return h === p;
}

export function hostMatchesAny(host: string, patterns: readonly string[]): boolean {
  return patterns.some((p) => hostMatches(host, p));
}

/**
 * Structural checks that apply to every outbound URL regardless of allowlist:
 * HTTPS only, no embedded credentials, no IP literals, default port only.
 */
export function checkUrl(raw: string): UrlCheck {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return { ok: false, reason: 'unparseable URL' };
  }
  if (url.protocol !== 'https:') return { ok: false, reason: `scheme ${url.protocol} is not allowed`, url };
  if (url.username || url.password) return { ok: false, reason: 'credentials embedded in URL', url };
  const host = url.hostname.toLowerCase();
  if (IPV4.test(host) || host.startsWith('[')) return { ok: false, reason: 'IP literal destinations are not allowed', url };
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local')) {
    return { ok: false, reason: 'internal hostname', url };
  }
  if (url.port && url.port !== '443') return { ok: false, reason: `non-default port ${url.port}`, url };
  return { ok: true, url };
}

/**
 * Every string an attacker could hide data in: the full URL, each decoded
 * query value, the decoded path and fragment, plus base64-decoded variants.
 */
export function urlDataSurfaces(url: URL): string[] {
  const surfaces = new Set<string>([url.href, safeDecode(url.pathname), safeDecode(url.hash)]);
  for (const [k, v] of url.searchParams) {
    surfaces.add(k);
    surfaces.add(v);
    const b64 = tryBase64(v);
    if (b64) surfaces.add(b64);
  }
  for (const seg of url.pathname.split('/')) {
    const b64 = tryBase64(safeDecode(seg));
    if (b64) surfaces.add(b64);
  }
  surfaces.delete('');
  return [...surfaces];
}

export function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** Decodes plausible base64/base64url payloads to printable text, else returns undefined. */
export function tryBase64(s: string): string | undefined {
  if (s.length < 12 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return undefined;
  try {
    const binary = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    const decoded = utf8.decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
    const printable = decoded.replace(/[^\x20-\x7E\n\t]/g, '');
    return printable.length >= decoded.length * 0.9 && printable.length >= 6 ? decoded : undefined;
  } catch {
    return undefined;
  }
}
