/**
 * Core types for the Axiom policy engine.
 *
 * The engine is deliberately stateless and deterministic: given the same
 * request, policy, clock and id generator it always produces the same result.
 */

/** Ordered from least to most restrictive. See `decision.ts`. */
export type Decision = 'allow' | 'sanitize' | 'escalate' | 'block';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** Where in the request lifecycle a rule applies. */
export type Stage = 'input' | 'context' | 'output' | 'action' | 'system';

/**
 * Provenance of a piece of context.
 * - `trusted`:   developer-authored configuration and policy text
 * - `internal`:  vetted internal knowledge (approved KB, policy docs)
 * - `untrusted`: anything a third party can influence (uploads, web pages, emails, tool output)
 */
export type TrustLevel = 'trusted' | 'internal' | 'untrusted';

/** Ordered from least to most sensitive. */
export type Sensitivity = 'public' | 'internal' | 'confidential' | 'restricted';

export interface Principal {
  userId?: string;
  roles: string[];
  /** Highest sensitivity this principal may read. Defaults to `internal`. */
  clearance: Sensitivity;
}

export interface ContextChunk {
  id: string;
  tenantId: string;
  /** Free-form origin label, e.g. `upload:application.pdf` or `web:example.com`. */
  source?: string;
  trust: TrustLevel;
  sensitivity: Sensitivity;
  /** If set, the principal must hold at least one of these roles. */
  allowedRoles?: string[];
  /** Text that would be placed in the model context. Optional so pure ACL checks stay cheap. */
  content?: string;
  /**
   * Explicit declassification: an authorized reviewer has vetted this untrusted
   * content. Declassified chunks no longer taint outbound actions.
   */
  declassifiedBy?: string;
}

export type ActionKind = 'http' | 'email' | 'tool' | 'memory' | 'export';

/** A side effect the model (or agent) proposes to perform. */
export interface ProposedAction {
  kind: ActionKind;
  /** URL for `http`, address for `email`, tool name for `tool`, key for `memory`, destination for `export`. */
  target: string;
  method?: string;
  /** Arguments / body. Scanned for sensitive data. */
  payload?: unknown;
}

export interface EvaluateRequest {
  tenantId: string;
  sessionId?: string;
  principal: Principal;
  /** The end-user's message. */
  input?: string;
  /** Retrieved or attached context, before it is handed to the model. */
  context?: ContextChunk[];
  /** The model's proposed response, before it is rendered. */
  output?: string;
  /** Side effects the model proposes, before they execute. */
  actions?: ProposedAction[];
}

export interface Finding {
  ruleId: string;
  stage: Stage;
  action: Decision;
  severity: Severity;
  message: string;
  /** What the finding is about: `input`, `output`, `context:<id>`, `action:<index>`. */
  target: string;
  /** Short, redacted excerpt that triggered the rule. Never contains raw sensitive values. */
  evidence?: string;
}

export interface AuthorizedChunk extends ContextChunk {
  /** True when the chunk is untrusted and has not been declassified. */
  tainted: boolean;
  /**
   * Content wrapped in provenance delimiters ("spotlighting") so the model can
   * tell data from instructions. Hidden unicode is stripped.
   */
  rendered?: string;
}

export interface DroppedChunk {
  id: string;
  reason: string;
  ruleId: string;
}

export interface ActionVerdict {
  index: number;
  kind: ActionKind;
  target: string;
  decision: Decision;
  ruleIds: string[];
}

export interface EvaluateResult {
  decision: Decision;
  findings: Finding[];
  /** Every rule that ran, matched or not. Lets auditors prove coverage. */
  rulesEvaluated: string[];
  context: {
    authorized: AuthorizedChunk[];
    dropped: DroppedChunk[];
    tainted: boolean;
  };
  /** Present when `input` was supplied: the input with invisible characters removed. */
  input?: {
    sanitized: string;
    modified: boolean;
  };
  /** Present when `output` was supplied. `sanitized` is safe to render if decision is `allow` or `sanitize`. */
  output?: {
    sanitized: string;
    modified: boolean;
  };
  actions: ActionVerdict[];
  audit: import('./audit/event.js').AuditEvent;
}
