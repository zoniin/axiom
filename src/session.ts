import type { Axiom } from './engine.js';
import type { StreamGuard } from './stream.js';
import type {
  ActionVerdict,
  AuthorizedChunk,
  ContextChunk,
  EvaluateRequest,
  EvaluateResult,
  ProposedAction,
  Sensitivity,
  TrustLevel,
} from './types.js';

type SessionBase = Omit<EvaluateRequest, 'context' | 'output' | 'actions'>;

/**
 * Stateful wrapper for multi-turn agents.
 *
 * `Axiom.evaluate` is stateless: taint only exists if the caller passes the
 * untrusted context back in. In a tool loop that is easy to get wrong. The
 * web page fetched three turns ago is no longer in the request, so the email
 * the model proposes now looks clean. A session keeps every chunk it has seen,
 * so taint lasts for the whole conversation until a reviewer declassifies it.
 */
export class AgentSession {
  private readonly chunks: ContextChunk[] = [];
  private readonly counters = new Map<string, number>();
  /** Every action checked in this session, in order. */
  readonly history: Array<{ action: ProposedAction; verdict: ActionVerdict; result: EvaluateResult }> = [];

  constructor(
    private readonly axiom: Axiom,
    readonly base: SessionBase,
  ) {}

  /** Context the model has seen so far (authorized chunks only). */
  get context(): readonly ContextChunk[] {
    return this.chunks;
  }

  /** True while any untrusted, non-declassified content is in the session. */
  get tainted(): boolean {
    return this.chunks.some((c) => c.trust === 'untrusted' && !c.declassifiedBy);
  }

  /**
   * Adds retrieved or attached context. Chunks that fail authorization are not
   * kept; the returned result says why.
   */
  addContext(chunks: ContextChunk[]): EvaluateResult {
    const result = this.axiom.evaluate({ ...this.base, context: [...this.chunks, ...chunks] });
    const authorized = new Set(result.context.authorized.map((c) => c.id));
    for (const c of chunks) if (authorized.has(c.id)) this.chunks.push(c);
    return result;
  }

  /**
   * Records a tool result. Tool output is untrusted by default: whoever controls
   * the web page, inbox or API behind the tool controls this text.
   * Returns the spotlighted chunk to hand back to the model.
   */
  recordToolResult(
    tool: string,
    content: string,
    options: { trust?: TrustLevel; sensitivity?: Sensitivity; id?: string } = {},
  ): AuthorizedChunk {
    const n = (this.counters.get(tool) ?? 0) + 1;
    this.counters.set(tool, n);
    const chunk: ContextChunk = {
      id: options.id ?? `tool:${tool}#${n}`,
      tenantId: this.base.tenantId,
      source: `tool:${tool}`,
      trust: options.trust ?? 'untrusted',
      sensitivity: options.sensitivity ?? 'internal',
      content,
    };
    this.chunks.push(chunk);
    const result = this.axiom.evaluate({ ...this.base, context: [chunk] }, { audit: false });
    return result.context.authorized[0] ?? { ...chunk, tainted: chunk.trust === 'untrusted' };
  }

  /** Marks a chunk as reviewed. It stops tainting later actions. */
  declassify(chunkId: string, reviewer: string): void {
    const c = this.chunks.find((x) => x.id === chunkId);
    if (!c) throw new Error(`No chunk ${chunkId} in this session.`);
    c.declassifiedBy = reviewer;
  }

  /** Checks one proposed side effect against policy and everything the session has seen. Audited. */
  checkAction(action: ProposedAction): { verdict: ActionVerdict; result: EvaluateResult } {
    const result = this.axiom.evaluate({ ...this.base, context: [...this.chunks], actions: [action] });
    const verdict = result.actions[0]!;
    this.history.push({ action, verdict, result });
    return { verdict, result };
  }

  /** Checks a model response before it is rendered. Audited. */
  checkOutput(output: string): EvaluateResult {
    return this.axiom.evaluate({ ...this.base, context: [...this.chunks], output });
  }

  /** Guards a streamed response with the session's context. */
  stream(): StreamGuard {
    return this.axiom.stream({ ...this.base, context: [...this.chunks] });
  }
}
