import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { AuditLog, MemoryAuditSink, guardStream, stableBoundary } from '../src/index.js';
import { runHarness, loadScenarios } from '../src/harness.js';
import { findActiveContent } from '../src/text/markdown.js';
import { axiom, req } from './helpers.js';

const base = req({ input: 'q' });

/** Splits text into chunks at the given cut points. */
function chunk(text: string, cuts: number[]): string[] {
  const points = [...new Set(cuts.map((c) => c % (text.length + 1)))].sort((a, b) => a - b);
  const out: string[] = [];
  let prev = 0;
  for (const p of points) {
    out.push(text.slice(prev, p));
    prev = p;
  }
  out.push(text.slice(prev));
  return out.filter(Boolean);
}

function runStream(ax: ReturnType<typeof axiom>, chunks: string[]) {
  const g = ax.stream(base);
  let text = '';
  for (const c of chunks) {
    const u = g.push(c);
    text += u.text;
    if (u.halted) break;
  }
  const end = g.end();
  return { text: text + end.text, end };
}

describe('stableBoundary', () => {
  it.each([
    ['hello wor', 'hello '],
    ['see ![alt](https://x', 'see '],
    ['click [here](https://e', 'click '],
    ['a <img src', 'a '],
    ['card 4111 1111 ', 'card '],
    ['ok [two words] more ', 'ok [two words] more '],
    ['text [label]', 'text '],
  ])('%j releases %j', (input, released) => {
    expect(input.slice(0, stableBoundary(input))).toBe(released);
  });
});

describe('StreamGuard', () => {
  it('releases clean text incrementally and matches the non-streamed result', () => {
    const ax = axiom();
    const g = ax.stream(base);
    expect(g.push('Your refund ').text).toBe('Your refund ');
    expect(g.push('will arr').text).toBe('will ');
    const end = g.end();
    expect(g.released).toBe('Your refund will arr');
    expect(end.result.decision).toBe('allow');
  });

  it('never releases any part of a markdown image beacon', () => {
    const ax = axiom();
    const tokens = ['Summary', ' done.', ' ![', 'x](https://evil', '.io/c?d=123-45', '-6789)', ' thanks'];
    const g = ax.stream(base);
    let shown = '';
    let halted = false;
    for (const t of tokens) {
      const u = g.push(t);
      shown += u.text;
      if (u.halted) {
        halted = true;
        break;
      }
    }
    expect(halted).toBe(true);
    expect(shown).toBe('Summary done. ');
    expect(g.end().result.decision).toBe('block');
  });

  it('redacts a card number split across chunks without leaking digits', () => {
    const { text } = runStream(axiom(), ['Card ', '4111 ', '1111 ', '1111 ', '1111', ' ok']);
    expect(text).toBe('Card [REDACTED:credit_card] ok');
  });

  it('halts on a commitment before the completing words are shown', () => {
    const ax = axiom({ commitments: { packs: ['finance'] } });
    const { text, end } = runStream(ax, ['Great news, ', 'you are ', 'pre-approved ', 'for a loan!']);
    expect(end.halted).toBe(true);
    expect(text).not.toContain('approved for');
  });

  it('audits only the final decision', () => {
    const sink = new MemoryAuditSink();
    const ax = axiom({}, { audit: new AuditLog([sink]) });
    runStream(ax, ['a ', 'b ', 'c ', 'd']);
    expect(sink.events).toHaveLength(1);
  });

  it('works as an async generator', async () => {
    async function* model() {
      yield 'Hello ';
      yield 'there, ';
      yield 'friend.';
    }
    const gen = guardStream(axiom(), base, model());
    const parts: string[] = [];
    let r = await gen.next();
    while (!r.done) {
      parts.push(r.value);
      r = await gen.next();
    }
    expect(parts.join('')).toBe('Hello there, friend.');
    expect(r.value.result.decision).toBe('allow');
  });
});

describe('streaming properties (fuzzed)', () => {
  const ax = axiom({ rendering: { linkAllowHosts: ['acme.com'] } });
  const outputs = loadScenarios()
    .map((s) => s.request.output)
    .filter((o): o is string => typeof o === 'string');

  it('for every harness output and every chunking: streamed == non-streamed, or the stream halted', () => {
    fc.assert(
      fc.property(fc.constantFrom(...outputs), fc.array(fc.nat(), { maxLength: 12 }), (output, cuts) => {
        const full = ax.evaluate({ ...base, output }, { audit: false });
        const { text, end } = runStream(ax, chunk(output, cuts));
        if (!end.halted) expect(text).toBe(full.output!.sanitized);
        // Released text never contains auto-fetching content, halted or not.
        expect(findActiveContent(text)).toEqual([]);
      }),
      { numRuns: 1500 },
    );
  });

  it('benign harness outputs stream without halting for any chunking', () => {
    const benign = runHarness().results.filter((r) => r.kind === 'benign').map((r) => r.id);
    const texts = loadScenarios().filter((s) => benign.includes(s.id) && s.request.output).map((s) => s.request.output!);
    fc.assert(
      fc.property(fc.constantFrom(...texts), fc.array(fc.nat(), { maxLength: 12 }), (output, cuts) => {
        expect(runStream(ax, chunk(output, cuts)).end.halted).toBe(false);
      }),
      { numRuns: 800 },
    );
  });
});
