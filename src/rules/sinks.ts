import type { Policy } from '../policy.js';
import type { Decision, ProposedAction } from '../types.js';
import { checkUrl, hostMatches, hostMatchesAny } from '../text/urls.js';
import type { Rule, RuleHit } from './rule.js';

interface SinkVerdict {
  action: Decision | 'none';
  reason: string;
}

/** Pure sink policy decision for one action. Exported for direct testing. */
export function evaluateSink(action: ProposedAction, policy: Policy): SinkVerdict {
  switch (action.kind) {
    case 'http': {
      const check = checkUrl(action.target);
      if (!check.ok || !check.url) return { action: 'block', reason: `Rejected URL: ${check.reason}.` };
      const url = check.url;
      const method = (action.method ?? 'GET').toUpperCase();
      const entry = policy.sinks.http.allow.find(
        (e) => hostMatches(url.hostname, e.host) && (!e.pathPrefix || url.pathname.startsWith(e.pathPrefix)),
      );
      if (!entry) return { action: 'block', reason: `Host ${url.hostname} is not an approved HTTP destination.` };
      if (!entry.methods.includes(method)) return { action: 'block', reason: `${method} is not allowed for ${url.hostname}.` };
      return { action: 'none', reason: 'Approved destination.' };
    }
    case 'email': {
      const recipients = action.target.split(/[,;]/).map((r) => r.trim()).filter(Boolean);
      if (recipients.length === 0) return { action: 'block', reason: 'No recipient.' };
      for (const r of recipients) {
        const m = /^[^@\s<>]+@([a-z0-9.-]+\.[a-z]{2,})$/i.exec(r);
        if (!m) return { action: 'block', reason: `Malformed recipient "${r}".` };
        if (!hostMatchesAny(m[1]!.toLowerCase(), policy.sinks.email.allowDomains)) {
          return { action: 'block', reason: `Recipient domain ${m[1]} is not approved.` };
        }
      }
      return { action: 'none', reason: 'Approved recipients.' };
    }
    case 'tool': {
      if (policy.sinks.tools.allow.includes(action.target)) return { action: 'none', reason: 'Approved tool.' };
      if (policy.sinks.tools.escalate.includes(action.target)) return { action: 'escalate', reason: `Tool ${action.target} requires approval.` };
      return { action: 'block', reason: `Tool ${action.target} is not registered in policy.` };
    }
    case 'memory':
    case 'export': {
      const mode = policy.sinks[action.kind];
      if (mode === 'allow') return { action: 'none', reason: `${action.kind} allowed by policy.` };
      if (mode === 'escalate') return { action: 'escalate', reason: `${action.kind} writes require approval.` };
      return { action: 'block', reason: `${action.kind} is denied by policy.` };
    }
    default:
      return { action: 'block', reason: 'Unknown action kind.' };
  }
}

export const sinkDefaultDeny: Rule = {
  id: 'AX-ACT-001',
  title: 'Outbound sink not approved',
  stage: 'action',
  severity: 'critical',
  defaultAction: 'block',
  locked: true,
  description:
    'Every side effect is default-deny. HTTP requires HTTPS, no credentials, no IP literals or internal names, default port, and an allowlisted host/method/path. Email requires allowlisted recipient domains. Tools must be registered. Memory and export follow their policy mode.',
  evaluate(ctx) {
    const hits: RuleHit[] = [];
    (ctx.request.actions ?? []).forEach((a, i) => {
      const v = evaluateSink(a, ctx.policy);
      if (v.action !== 'none') hits.push({ target: `action:${i}`, action: v.action, message: v.reason });
    });
    return hits;
  },
};

export const taintedAction: Rule = {
  id: 'AX-ACT-002',
  title: 'Action proposed while context is tainted',
  stage: 'action',
  severity: 'high',
  defaultAction: 'escalate',
  locked: true,
  description:
    'When untrusted, non-declassified content is in the model context, any proposed side effect requires human approval, and memory writes are blocked outright. This is what stops indirect prompt injection even when detection misses it.',
  evaluate(ctx) {
    if (!ctx.tainted) return [];
    const sources = ctx.authorizedContext.filter((c) => c.trust === 'untrusted' && !c.declassifiedBy).map((c) => c.id);
    return (ctx.request.actions ?? []).map((a, i): RuleHit => {
      const list = sources.join(', ');
      return a.kind === 'memory'
        ? { target: `action:${i}`, action: 'block', message: `Memory write while context is tainted by [${list}]. Declassify first.` }
        : { target: `action:${i}`, message: `${a.kind} action while context is tainted by [${list}].` };
    });
  },
};

export const untrustedDestination: Rule = {
  id: 'AX-ACT-003',
  title: 'Destination supplied by untrusted content',
  stage: 'action',
  severity: 'critical',
  defaultAction: 'block',
  locked: true,
  description:
    'The host or email address of an action appears in untrusted context. Untrusted content may inform answers but may never choose where data goes.',
  evaluate(ctx) {
    const untrusted = ctx.authorizedContext
      .filter((c) => c.trust === 'untrusted' && !c.declassifiedBy)
      .map((c) => [c.id, (ctx.normalized.context.get(c.id) ?? '').toLowerCase()] as const)
      .filter(([, t]) => t.length > 0);
    if (untrusted.length === 0) return [];
    const hits: RuleHit[] = [];
    (ctx.request.actions ?? []).forEach((a, i) => {
      const needles = destinationNeedles(a);
      for (const [id, text] of untrusted) {
        const needle = needles.find((n) => containsToken(text, n));
        if (needle) {
          hits.push({ target: `action:${i}`, message: `Destination "${needle}" was supplied by untrusted chunk ${id}.` });
          return;
        }
      }
    });
    return hits;
  },
};

function destinationNeedles(a: ProposedAction): string[] {
  if (a.kind === 'http') {
    try {
      return [new URL(a.target).hostname.toLowerCase()];
    } catch {
      return [];
    }
  }
  if (a.kind === 'email') return a.target.split(/[,;]/).map((r) => r.trim().toLowerCase()).filter(Boolean);
  return [];
}

function containsToken(haystack: string, needle: string): boolean {
  let from = 0;
  for (;;) {
    const i = haystack.indexOf(needle, from);
    if (i < 0) return false;
    const before = haystack[i - 1] ?? ' ';
    const after = haystack[i + needle.length] ?? ' ';
    if (!/[a-z0-9.-]/.test(before) && !/[a-z0-9-]/.test(after)) return true;
    from = i + 1;
  }
}
