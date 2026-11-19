import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { DLP_DETECTORS, sanitizeOutput, parsePolicy } from '../src/index.js';
import { scanSensitive } from '../src/text/dlp.js';
import { findActiveContent } from '../src/text/markdown.js';
import { normalizeForMatching } from '../src/text/normalize.js';
import { axiom, req } from './helpers.js';

/**
 * Property-based tests: invariants from SECURITY.md checked against thousands
 * of generated adversarial inputs built from exfiltration-relevant fragments.
 */

const FRAGMENTS = [
  '![', '](', ')', '[', ']', '(', '<', '>', '"', "'", ' ', '\n', '!', ':', '=',
  'https://evil.io/c?d=', 'http://x.io', 'javascript:', 'data:text/html,', 'JaVaScRiPt:', 'vbscript:',
  '<img src=', '<IMG SRC=', '<svg', '<script>', '</script>', '<iframe', '<style>', 'onload=', 'onerror=',
  ' style="background:url(', '[r]: https://e.io/x', '![a][r]', 'src=', 'href=',
  '123-45-6789', '4111 1111 1111 1111', 'AKIAIOSFODNN7EXAMPLE', 'hello', 'refund', 'acme.com',
  String.fromCodePoint(0x200b), String.fromCodePoint(0x202e), String.fromCodePoint(0xe0041),
];
const adversarial = fc.array(fc.constantFrom(...FRAGMENTS), { maxLength: 40 }).map((p) => p.join(''));
const anyText = fc.oneof(adversarial, fc.string({ maxLength: 200 }), fc.string({ unit: 'grapheme', maxLength: 80 }));

const policy = parsePolicy({});
const runs = { numRuns: 3000 };

describe('invariants (fuzzed)', () => {
  it('sanitized output never contains auto-fetching or executable content', () => {
    fc.assert(
      fc.property(anyText, (text) => {
        expect(findActiveContent(sanitizeOutput(text, policy))).toEqual([]);
      }),
      runs,
    );
  });

  it('redaction is complete: nothing a DLP detector would flag survives sanitization', () => {
    fc.assert(
      fc.property(adversarial, (text) => {
        expect(scanSensitive(normalizeForMatching(sanitizeOutput(text, policy)), policy.dlp.detectors)).toEqual([]);
      }),
      runs,
    );
  });

  it('secrets glued to letters or symbols are still redacted', () => {
    const glue = fc.constantFrom('', 'x', 'hello', '=', 'javascript:', '<', ')', '"');
    const secret = fc.constantFrom('123-45-6789', '4111 1111 1111 1111', 'AKIAIOSFODNN7EXAMPLE');
    fc.assert(
      fc.property(glue, secret, glue, (a, s, b) => {
        expect(sanitizeOutput(`${a}${s}${b}`, policy)).not.toContain(s);
      }),
      { numRuns: 500 },
    );
  });

  it('sanitization is idempotent', () => {
    fc.assert(
      fc.property(anyText, (text) => {
        const once = sanitizeOutput(text, policy);
        expect(sanitizeOutput(once, policy)).toBe(once);
      }),
      runs,
    );
  });

  it('output with active content is never allowed', () => {
    const ax = axiom();
    fc.assert(
      fc.property(anyText, (text) => {
        const r = ax.evaluate(req({ output: text }), { audit: false });
        if (findActiveContent(text.normalize('NFC')).length > 0) expect(r.decision).toBe('block');
      }),
      runs,
    );
  });

  it('a cross-tenant chunk always blocks and never reaches authorized context, whatever else is present', () => {
    const ax = axiom({ sinks: { tools: { allow: ['t'] }, memory: 'allow' } });
    fc.assert(
      fc.property(anyText, anyText, fc.boolean(), (input, content, withAction) => {
        const r = ax.evaluate(
          req({
            input,
            context: [{ id: 'x', tenantId: 'other', trust: 'internal', sensitivity: 'public', content }],
            actions: withAction ? [{ kind: 'tool', target: 't' }] : [],
          }),
          { audit: false },
        );
        expect(r.decision).toBe('block');
        expect(r.context.authorized).toEqual([]);
      }),
      { numRuns: 1000 },
    );
  });

  it('tainted context never allows an action', () => {
    const ax = axiom({ sinks: { tools: { allow: ['t'] }, memory: 'allow', http: { allow: [{ host: 'a.com' }] } } });
    const action = fc.constantFrom(
      { kind: 'tool' as const, target: 't' },
      { kind: 'memory' as const, target: 'k' },
      { kind: 'http' as const, target: 'https://a.com/x' },
    );
    fc.assert(
      fc.property(anyText, action, (content, a) => {
        const r = ax.evaluate(req({ context: [{ id: 'u', tenantId: 't1', trust: 'untrusted', sensitivity: 'public', content }], actions: [a] }), { audit: false });
        expect(r.actions[0]!.decision).not.toBe('allow');
      }),
      { numRuns: 1000 },
    );
  });

  it('audit events never contain raw sensitive values', () => {
    const ax = axiom({ sinks: { http: { allow: [{ host: 'a.com' }] } } });
    fc.assert(
      fc.property(adversarial, adversarial, (input, output) => {
        const r = ax.evaluate(req({ input, output, actions: [{ kind: 'http', target: `https://a.com/?q=${encodeURIComponent(output)}` }] }), { audit: false });
        const detectors = DLP_DETECTORS.filter((d) => d !== 'email_address');
        // Hex digests can contain Luhn-valid digit runs by chance; they are hashes, not data.
        const { requestDigest: _d, policy: _p, ...rest } = r.audit;
        expect(scanSensitive(JSON.stringify(rest), detectors)).toEqual([]);
      }),
      { numRuns: 1500 },
    );
  });

  it('evaluation is deterministic', () => {
    fc.assert(
      fc.property(anyText, anyText, (input, output) => {
        expect(axiom().evaluate(req({ input, output }))).toEqual(axiom().evaluate(req({ input, output })));
      }),
      { numRuns: 500 },
    );
  });
});
