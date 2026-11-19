import type { Axiom } from './engine.js';
import type { EvaluateRequest, EvaluateResult, Finding } from './types.js';

/**
 * Guards streamed model output. Real apps stream tokens to the user, and a
 * markdown image beacon only needs to *render* once to leak, so checking the
 * finished response is too late.
 *
 * The guard keeps a buffer and only releases a prefix that can no longer
 * change meaning: anything after an unclosed `[`, `(`, `<` or `![`, the
 * trailing word (URLs and tokens still growing), and trailing digit runs (card
 * numbers span spaces) are held back. The released prefix is run through the
 * full engine before a single character is emitted.
 *
 * The stream halts (fails closed) when:
 * - an output finding would `escalate` or `block`, e.g. an image, a canary, a commitment
 * - the sanitized prefix stops being a prefix of what was already emitted,
 *   which means earlier text changed meaning in a way that can't be retracted
 *
 * Only the final evaluation (on `end()` or on halt) is written to the audit log.
 */
export class StreamGuard {
  private buffer = '';
  private emitted = '';
  private haltedResult: EvaluateResult | undefined;
  private haltReason: string | undefined;

  constructor(
    private readonly axiom: Axiom,
    private readonly base: Omit<EvaluateRequest, 'output' | 'actions'>,
  ) {}

  get halted(): boolean {
    return this.haltedResult !== undefined;
  }

  /** Text released so far. */
  get released(): string {
    return this.emitted;
  }

  push(chunk: string): StreamUpdate {
    if (this.haltedResult) return { text: '', halted: true };
    this.buffer += chunk;
    const prefix = this.buffer.slice(0, stableBoundary(this.buffer));
    if (prefix.length === 0) return { text: '', halted: false };

    const r = this.axiom.evaluate({ ...this.base, output: prefix }, { audit: false });
    const blocking = outputBlockers(r.findings);
    if (blocking.length > 0) return this.halt(`${blocking.map((f) => f.ruleId).join(', ')} on streamed output`);

    const sanitized = r.output?.sanitized ?? '';
    if (!sanitized.startsWith(this.emitted)) return this.halt('sanitized stream diverged from released text');
    const text = sanitized.slice(this.emitted.length);
    this.emitted = sanitized;
    return { text, halted: false };
  }

  /** Flushes held-back text after a final, audited evaluation of the whole output. */
  end(): StreamEnd {
    if (this.haltedResult) return { text: '', halted: true, reason: this.haltReason, result: this.haltedResult };
    const result = this.axiom.evaluate({ ...this.base, output: this.buffer });
    const blocking = outputBlockers(result.findings);
    const sanitized = result.output?.sanitized ?? '';
    if (blocking.length > 0) {
      return { text: '', halted: true, reason: `${blocking.map((f) => f.ruleId).join(', ')} on streamed output`, result };
    }
    if (!sanitized.startsWith(this.emitted)) return { text: '', halted: true, reason: 'sanitized stream diverged from released text', result };
    const text = sanitized.slice(this.emitted.length);
    this.emitted = sanitized;
    return { text, halted: false, result };
  }

  private halt(reason: string): StreamUpdate {
    this.haltReason = reason;
    this.haltedResult = this.axiom.evaluate({ ...this.base, output: this.buffer });
    return { text: '', halted: true, reason };
  }
}

export interface StreamUpdate {
  /** Newly released, checked text. Safe to send to the client. */
  text: string;
  halted: boolean;
  reason?: string;
}

export interface StreamEnd extends StreamUpdate {
  /** Final audited evaluation of everything the model produced. */
  result: EvaluateResult;
}

/**
 * Convenience wrapper: yields checked text from a token stream and returns the
 * final result. On halt it stops reading from the source.
 */
export async function* guardStream(
  axiom: Axiom,
  base: Omit<EvaluateRequest, 'output' | 'actions'>,
  source: AsyncIterable<string>,
): AsyncGenerator<string, StreamEnd> {
  const guard = new StreamGuard(axiom, base);
  for await (const chunk of source) {
    const u = guard.push(chunk);
    if (u.text) yield u.text;
    if (u.halted) return guard.end();
  }
  const end = guard.end();
  if (end.text) yield end.text;
  return end;
}

function outputBlockers(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.target === 'output' && (f.action === 'block' || f.action === 'escalate'));
}

/**
 * Length of the longest prefix of `text` whose meaning can't change when more
 * text arrives. Conservative: holding back too much only adds latency.
 */
export function stableBoundary(text: string): number {
  // 1. Only release up to the last whitespace: the trailing word may still be growing.
  let b = lastWhitespaceEnd(text);
  // 2. Unclosed brackets, parens or angle brackets: hold from the opener (and a preceding `!`).
  b = Math.min(b, earliestUnclosed(text.slice(0, b)));
  // 3. A reference definition line (`[x]: url "title"`) or PEM header still being written.
  const lineStart = text.lastIndexOf('\n', b - 1) + 1;
  const line = text.slice(lineStart, b);
  if (/^[ \t]{0,3}\[[^\]]*\]:/.test(line) || line.includes('-----')) b = Math.min(b, lineStart);
  // 4. Trailing digit runs (cards and SSNs can contain spaces).
  const head = text.slice(0, b);
  const digits = /\d[\d \t-]*$/.exec(head);
  if (digits) b = digits.index;
  // Never split a surrogate pair.
  if (b > 0 && b < text.length && /[\uD800-\uDBFF]/.test(text[b - 1]!)) b--;
  return b;
}

function lastWhitespaceEnd(text: string): number {
  for (let i = text.length - 1; i >= 0; i--) if (/\s/.test(text[i]!)) return i + 1;
  return 0;
}

function earliestUnclosed(text: string): number {
  const stack: Array<{ ch: string; at: number }> = [];
  const pairs: Record<string, string> = { ']': '[', ')': '(', '>': '<' };
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '[' || c === '(' || c === '<') stack.push({ ch: c, at: i });
    else if (c in pairs) {
      const idx = stack.map((s) => s.ch).lastIndexOf(pairs[c]!);
      if (idx >= 0) stack.splice(idx);
    }
  }
  // `[label]` followed directly by `(` would be a link; if the text ends at `]`, it's ambiguous.
  if (text.endsWith(']')) {
    const open = text.lastIndexOf('[');
    if (open >= 0) stack.push({ ch: '[', at: open });
  }
  if (stack.length === 0) return text.length;
  let at = Math.min(...stack.map((s) => s.at));
  if (at > 0 && text[at - 1] === '!') at--;
  return at;
}
