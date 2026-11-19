import type { Decision, Severity } from '../types.js';

export const AUDIT_SCHEMA = 'axiom.audit/v1';

/**
 * One audit event per evaluation. Events never contain raw prompt, context or
 * output text: only rule IDs, targets, masked evidence and a request digest,
 * so the audit log itself does not become a sensitive-data store.
 */
export interface AuditEvent {
  schema: typeof AUDIT_SCHEMA;
  eventId: string;
  timestamp: string;
  tenantId: string;
  sessionId?: string;
  userId?: string;
  decision: Decision;
  policy: { name: string; hash: string };
  /** SHA-256 of the canonical request. Lets you prove which request produced this decision. */
  requestDigest: string;
  rulesEvaluated: string[];
  findings: Array<{ ruleId: string; action: Decision; severity: Severity; target: string; message: string; evidence?: string }>;
  context: { authorized: string[]; dropped: string[]; tainted: boolean };
  actions: Array<{ index: number; kind: string; destination: string; decision: Decision }>;
  /** Set when the event is appended to an `AuditLog`. */
  seq?: number;
  prevHash?: string;
  hash?: string;
}
