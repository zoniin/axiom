import crypto from 'node:crypto';
import type { Decision, EvaluateRequest, EvaluateResponse, RuleResult } from './types.js';

const DIRECT_INJECTION = [/ignore\s+(all\s+)?previous\s+instructions/i, /reveal\s+(the\s+)?system\s+prompt/i, /developer\s+message/i];
const MARKDOWN_IMAGE = /!\[[^\]]*\]\([^\)]*\)/i;
const HTML_IMAGE = /<img\b/i;
const DANGEROUS_URI = /(?:javascript|data|file):/i;
const SSN = /\b\d{3}-\d{2}-\d{4}\b/;
const COMMITMENT = /\b(guaranteed approval|approved for|guarantee an apr|waive (your )?fee|legally binding|denial reason is)\b/i;

const APPROVED_HOSTS = new Set(['upstart.com', 'www.upstart.com', 'upstartnetwork.com']);

export function evaluatePolicy(req: EvaluateRequest): EvaluateResponse {
  const results: RuleResult[] = [];
  const fullText = `${req.input}\n${req.proposedOutput ?? ''}`;

  add(results, 'AX-PI-007', DIRECT_INJECTION.some((r) => r.test(req.input)), 'escalate', 'Direct instruction override pattern detected.');
  add(results, 'AX-PI-001', MARKDOWN_IMAGE.test(fullText) || HTML_IMAGE.test(fullText) || DANGEROUS_URI.test(fullText), 'block', 'Auto-fetching or dangerous rendering detected.');
  add(results, 'AX-PI-003', SSN.test(fullText), 'block', 'Sensitive identifier detected in rendered text or sink arguments.');
  add(results, 'AX-PI-006', COMMITMENT.test(req.proposedOutput ?? ''), 'escalate', 'Potential unsupported financial or policy commitment detected.');

  const crossTenant = req.retrievedChunks.some((chunk) => chunk.tenantId !== req.tenantId);
  add(results, 'AX-PI-004', crossTenant, 'block', 'Retrieved chunk tenant does not match request tenant.');

  for (const sink of req.proposedSinks) {
    if (sink.type === 'url' || sink.type === 'webhook') {
      const url = sink.url ?? sink.destination ?? '';
      const allowed = isApprovedUrl(url);
      add(results, 'AX-PI-002', !allowed, 'block', `Unapproved outbound destination: ${url || 'missing url'}`);
      add(results, 'AX-PI-003', SSN.test(url), 'block', 'Sensitive identifier detected in outbound URL.');
    } else if (['email', 'export', 'tool', 'memory'].includes(sink.type)) {
      add(results, 'AX-PI-005', true, 'escalate', `High-risk sink requires explicit policy approval: ${sink.type}`);
    }
  }

  const decision = reduceDecision(results);
  return {
    decision,
    ruleResults: results,
    auditEvent: {
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      tenantId: req.tenantId,
      userId: req.userId,
      sessionId: req.sessionId,
      channel: req.channel,
      decision,
      retrievedChunkIds: req.retrievedChunks.map((c) => c.chunkId),
      proposedSinks: req.proposedSinks,
      ruleResults: results,
    },
  };
}

function add(results: RuleResult[], ruleId: string, matched: boolean, action: Decision, reason: string) {
  results.push({ ruleId, matched, action: matched ? action : 'none', reason: matched ? reason : 'No match.' });
}

function reduceDecision(results: RuleResult[]): Decision {
  if (results.some((r) => r.matched && r.action === 'block')) return 'block';
  if (results.some((r) => r.matched && r.action === 'escalate')) return 'escalate';
  return 'allow';
}

function isApprovedUrl(raw: string): boolean {
  try {
    const url = new URL(raw);
    if (!['https:'].includes(url.protocol)) return false;
    return APPROVED_HOSTS.has(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}
