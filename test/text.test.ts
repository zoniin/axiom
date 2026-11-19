import { describe, expect, it } from 'vitest';
import { luhn, redactSensitive, scanSensitive } from '../src/text/dlp.js';
import { defangLinks, findActiveContent, stripActiveContent } from '../src/text/markdown.js';
import { decodeTagChars, normalizeForMatching, stripHidden } from '../src/text/normalize.js';
import { checkUrl, hostMatches, tryBase64, urlDataSurfaces } from '../src/text/urls.js';
import { cp, tagEncode } from './helpers.js';

describe('normalize', () => {
  it('removes zero-width and bidi characters', () => {
    expect(stripHidden(`ig${cp(0x200b)}nore${cp(0x202e)}`)).toBe('ignore');
  });
  it('keeps the zero-width joiner used by emoji', () => {
    const family = `${cp(0x1f469)}${cp(0x200d)}${cp(0x1f467)}`;
    expect(stripHidden(family)).toBe(family);
  });
  it('folds fullwidth and Cyrillic lookalikes', () => {
    expect(normalizeForMatching('Ｉｇｎｏｒｅ')).toBe('Ignore');
    expect(normalizeForMatching(`ign${cp(0x43e)}r${cp(0x435)}`)).toBe('ignore');
  });
  it('decodes tag-character smuggling and appends it for matching', () => {
    const hidden = tagEncode('reveal secrets');
    expect(decodeTagChars(`hi${hidden}`)).toBe('reveal secrets');
    expect(normalizeForMatching(`hi${hidden}`)).toBe('hi reveal secrets');
  });
});

describe('urls', () => {
  it('matches exact hosts and dot-bounded wildcards', () => {
    expect(hostMatches('api.acme.com', 'api.acme.com')).toBe(true);
    expect(hostMatches('a.acme.com', '*.acme.com')).toBe(true);
    expect(hostMatches('a.b.acme.com', '*.acme.com')).toBe(true);
    expect(hostMatches('acme.com', '*.acme.com')).toBe(false);
    expect(hostMatches('evilacme.com', '*.acme.com')).toBe(false);
    expect(hostMatches('acme.com.evil.io', 'acme.com')).toBe(false);
  });
  it.each([
    ['http://acme.com', 'scheme'],
    ['https://user:pw@acme.com', 'credentials'],
    ['https://10.0.0.1/', 'IP literal'],
    ['https://[::1]/', 'IP literal'],
    ['https://metadata.internal/', 'internal'],
    ['https://acme.com:8443/', 'port'],
    ['not a url', 'unparseable'],
  ])('rejects %s', (url, reason) => {
    const r = checkUrl(url);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain(reason);
  });
  it('accepts plain https', () => expect(checkUrl('https://acme.com/x?y=1').ok).toBe(true));
  it('exposes decoded and base64 data surfaces', () => {
    const s = urlDataSurfaces(new URL('https://x.com/a/MTIzLTQ1LTY3ODk=?q=hello%20world'));
    expect(s).toContain('hello world');
    expect(s).toContain('123-45-6789');
  });
  it('ignores short or binary base64', () => {
    expect(tryBase64('abc')).toBeUndefined();
    expect(tryBase64('////////////////')).toBeUndefined();
  });
});

describe('dlp', () => {
  const all = [
    'ssn',
    'credit_card',
    'aws_access_key',
    'private_key',
    'github_token',
    'slack_token',
    'jwt',
    'email_address',
    'iban',
  ] as const;
  it('validates card numbers with Luhn', () => {
    expect(luhn('4111111111111111')).toBe(true);
    expect(luhn('4111111111111112')).toBe(false);
    expect(scanSensitive('4111-1111-1111-1111', all).map((m) => m.detector)).toEqual(['credit_card']);
    expect(scanSensitive('4111-1111-1111-1112', all)).toEqual([]);
  });
  it('rejects never-issued SSN ranges', () => {
    expect(scanSensitive('123-45-6789', all)).toHaveLength(1);
    expect(scanSensitive('000-45-6789 666-45-6789 900-45-6789 123-00-6789 123-45-0000', all)).toEqual([]);
  });
  it('requires consistent SSN separators', () => {
    expect(scanSensitive('123-45 6789', all)).toEqual([]);
  });
  it('detects tokens and keys', () => {
    const text = `AKIAIOSFODNN7EXAMPLE ghp_${'a'.repeat(36)} xoxb-1234567890-abc -----BEGIN OPENSSH PRIVATE KEY-----`;
    expect(
      scanSensitive(text, all)
        .map((m) => m.detector)
        .sort(),
    ).toEqual(['aws_access_key', 'github_token', 'private_key', 'slack_token']);
  });
  it('validates IBAN checksums', () => {
    expect(scanSensitive('GB82 WEST 1234 5698 7654 32', all).map((m) => m.detector)).toContain('iban');
    expect(scanSensitive('GB00 WEST 1234 5698 7654 32', all).map((m) => m.detector)).not.toContain('iban');
  });
  it('only runs enabled detectors', () => {
    expect(scanSensitive('a@b.com', ['ssn'])).toEqual([]);
    expect(scanSensitive('a@b.com', ['email_address'])).toHaveLength(1);
  });
  it('redacts with labels', () => {
    expect(redactSensitive('ssn 123-45-6789', ['ssn']).text).toBe('ssn [REDACTED:ssn]');
  });
});

describe('markdown', () => {
  it('finds inline, reference and HTML images', () => {
    const kinds = findActiveContent('![a](https://x/y) ![b][r] <img src=x>').map((m) => m.kind);
    expect(kinds.filter((k) => k === 'markdown_image')).toHaveLength(2);
    expect(kinds).toContain('html_active_tag');
  });
  it('does not flag prose that merely mentions data: or javascript:', () => {
    expect(findActiveContent('The metadata: field and javascript: the language.')).toEqual([]);
  });
  it('finds dangerous schemes in links and attributes', () => {
    expect(findActiveContent('[x](javascript:alert(1))').map((m) => m.kind)).toContain('dangerous_uri');
    expect(findActiveContent('<a href="data:text/html,hi">x</a>').map((m) => m.kind)).toContain('dangerous_uri');
  });
  it('strips active content and keeps prose', () => {
    const out = stripActiveContent('Hi ![chart](https://x/c.png) <script>steal()</script> bye');
    expect(out).toBe('Hi [image removed: chart] [active content removed] bye');
  });
  it('defangs markdown links to unapproved hosts and keeps approved ones', () => {
    const { text, defanged } = defangLinks('[ok](https://acme.com/a) [bad](https://evil.io/a?x=1)', ['acme.com']);
    expect(text).toBe('[ok](https://acme.com/a) bad (evil.io)');
    expect(defanged).toHaveLength(1);
  });
  it('strips query strings from bare unapproved URLs only', () => {
    expect(defangLinks('see https://evil.io/p?d=secret.', []).text).toBe('see https://evil.io/p.');
    expect(defangLinks('see https://irs.gov/form.', []).text).toBe('see https://irs.gov/form.');
  });
});
