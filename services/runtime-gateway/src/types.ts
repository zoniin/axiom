export type Decision = 'allow' | 'block' | 'escalate';

export interface ProposedSink {
  type: 'url' | 'webhook' | 'email' | 'export' | 'memory' | 'tool';
  url?: string;
  destination?: string;
  args?: Record<string, unknown>;
}

export interface RetrievedChunk {
  chunkId: string;
  tenantId: string;
  trustClass: 'trusted' | 'internal' | 'untrusted' | 'generated';
  sensitivity: 'public' | 'internal' | 'pii' | 'npi';
  allowedRoles?: string[];
}

export interface EvaluateRequest {
  tenantId: string;
  userId?: string;
  sessionId?: string;
  role?: string;
  channel: 'chat' | 'rag' | 'agent' | 'api';
  input: string;
  retrievedChunks: RetrievedChunk[];
  proposedOutput?: string;
  proposedSinks: ProposedSink[];
}

export interface RuleResult {
  ruleId: string;
  matched: boolean;
  action: Decision | 'none';
  reason: string;
}

export interface EvaluateResponse {
  decision: Decision;
  ruleResults: RuleResult[];
  auditEvent: Record<string, unknown>;
}
