import type { Policy } from '../policy.js';
import type { ContextChunk, Decision, EvaluateRequest, Severity, Stage } from '../types.js';

/** What a rule sees. Context rules see every chunk; later rules see only authorized chunks. */
export interface RuleContext {
  request: EvaluateRequest;
  policy: Policy;
  /** NFKC-normalized, invisible-character-free, confusable-folded text. */
  normalized: {
    input?: string;
    output?: string;
    context: Map<string, string>;
  };
  /** Chunks that passed retrieval authorization. Empty during the authorization pass. */
  authorizedContext: ContextChunk[];
  /** True when any authorized chunk is untrusted and not declassified. */
  tainted: boolean;
}

export interface RuleHit {
  /** `input`, `output`, `context:<id>` or `action:<index>`. */
  target: string;
  message: string;
  evidence?: string;
  /** Overrides the rule's default action for this hit (e.g. a stricter variant). */
  action?: Decision;
  severity?: Severity;
  /** Context rules only: remove this chunk before it reaches the model. */
  drop?: boolean;
}

export interface Rule {
  id: string;
  title: string;
  stage: Stage;
  severity: Severity;
  defaultAction: Decision;
  /**
   * Locked rules guard core invariants (tenant isolation, default-deny sinks,
   * prompt leaks). Policy overrides may make them stricter, never weaker.
   */
  locked?: boolean;
  description: string;
  evaluate(ctx: RuleContext): RuleHit[];
}

/** Truncates and single-lines a piece of text for use as audit evidence. */
export function excerpt(text: string, max = 80): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}
