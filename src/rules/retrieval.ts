import { sensitivityRank } from '../decision.js';
import { DIRECT_PATTERNS, INDIRECT_PATTERNS, matchPatterns } from './patterns.js';
import { excerpt, type Rule, type RuleHit } from './rule.js';

export const tenantIsolation: Rule = {
  id: 'AX-CTX-001',
  title: 'Cross-tenant context',
  stage: 'context',
  severity: 'critical',
  defaultAction: 'block',
  locked: true,
  description:
    'A retrieved chunk belongs to a different tenant than the request. The chunk is dropped and the request blocked: this indicates a broken index or a filter bypass and must fail closed.',
  evaluate(ctx) {
    return (ctx.request.context ?? [])
      .filter((c) => c.tenantId !== ctx.request.tenantId)
      .map((c) => ({
        target: `context:${c.id}`,
        drop: true,
        message: `Chunk belongs to tenant "${c.tenantId}", request is for "${ctx.request.tenantId}".`,
      }));
  },
};

export const accessAuthorization: Rule = {
  id: 'AX-CTX-002',
  title: 'Context not authorized for principal',
  stage: 'context',
  severity: 'high',
  defaultAction: 'sanitize',
  locked: true,
  description:
    "Drops chunks the principal may not read (role or clearance mismatch) before they reach the model. The rest of the request proceeds.",
  evaluate(ctx) {
    const { principal } = ctx.request;
    const hits: RuleHit[] = [];
    for (const c of ctx.request.context ?? []) {
      if (c.tenantId !== ctx.request.tenantId) continue; // handled by AX-CTX-001
      if (c.allowedRoles && c.allowedRoles.length > 0 && !c.allowedRoles.some((r) => principal.roles.includes(r))) {
        hits.push({ target: `context:${c.id}`, drop: true, message: `Principal lacks any of roles [${c.allowedRoles.join(', ')}].` });
      } else if (sensitivityRank(c.sensitivity) > sensitivityRank(principal.clearance)) {
        hits.push({ target: `context:${c.id}`, drop: true, message: `Chunk is ${c.sensitivity}; principal clearance is ${principal.clearance}.` });
      }
    }
    return hits;
  },
};

export const indirectInjection: Rule = {
  id: 'AX-CTX-003',
  title: 'Instructions embedded in untrusted context',
  stage: 'context',
  severity: 'high',
  defaultAction: 'escalate',
  description:
    'Untrusted content (uploads, web pages, emails, tool results) contains text addressed to the model. Taint tracking already prevents it from driving actions; this rule surfaces the attempt.',
  evaluate(ctx) {
    const hits: RuleHit[] = [];
    for (const c of ctx.authorizedContext) {
      if (c.trust !== 'untrusted' || c.declassifiedBy) continue;
      const text = ctx.normalized.context.get(c.id);
      if (!text) continue;
      const found = matchPatterns(text, [...DIRECT_PATTERNS, ...INDIRECT_PATTERNS]);
      if (found.length === 0) continue;
      hits.push({
        target: `context:${c.id}`,
        message: `Untrusted ${c.source ?? 'content'} contains instructions (${found.map((f) => f.id).join(', ')}).`,
        evidence: excerpt(found[0]!.match),
      });
    }
    return hits;
  },
};
