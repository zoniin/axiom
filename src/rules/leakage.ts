import { type DlpMatch, maskValue, scanSensitive } from '../text/dlp.js';
import { findLinks } from '../text/markdown.js';
import { normalizeForMatching } from '../text/normalize.js';
import { urlDataSurfaces } from '../text/urls.js';
import type { Rule, RuleHit } from './rule.js';
import { actionSurfaces } from './surfaces.js';

export const canaryLeak: Rule = {
  id: 'AX-OUT-003',
  title: 'System prompt canary leaked',
  stage: 'output',
  severity: 'critical',
  defaultAction: 'block',
  locked: true,
  description:
    'A canary token planted in the system prompt appears in output or action arguments. This is deterministic proof that hidden instructions are being exfiltrated.',
  evaluate(ctx) {
    const canaries = ctx.policy.canaries;
    if (canaries.length === 0) return [];
    const hits: RuleHit[] = [];
    const leaked = (texts: string[]) =>
      canaries.some((c) => texts.some((t) => t.includes(c) || normalizeForMatching(t).replace(/\s/g, '').includes(c)));
    if (ctx.request.output && leaked([ctx.request.output])) {
      hits.push({ target: 'output', message: 'Output contains a system-prompt canary token.' });
    }
    (ctx.request.actions ?? []).forEach((a, i) => {
      if (leaked(actionSurfaces(a)))
        hits.push({ target: `action:${i}`, message: 'Action arguments contain a system-prompt canary token.' });
    });
    return hits;
  },
};

export const sensitiveOutput: Rule = {
  id: 'AX-DLP-001',
  title: 'Sensitive data in output',
  stage: 'output',
  severity: 'high',
  defaultAction: 'sanitize',
  description:
    'Structurally validated secrets and identifiers (SSN, Luhn-valid card numbers, cloud keys, tokens, private keys) in model output are redacted, or the response is blocked, per `dlp.output`.',
  evaluate(ctx) {
    if (!ctx.request.output) return [];
    const output = ctx.request.output;
    const surfaces = [normalizeForMatching(output)];
    // Data hidden in link URLs (percent- or base64-encoded) counts too.
    for (const link of findLinks(output)) {
      try {
        surfaces.push(...urlDataSurfaces(new URL(link.url)));
      } catch {
        /* not a URL */
      }
    }
    const found = dedupe(surfaces.flatMap((s) => scanSensitive(s, ctx.policy.dlp.detectors)));
    if (found.length === 0) return [];
    return [
      {
        target: 'output',
        action: ctx.policy.dlp.output,
        message: `Output contains ${found.length} sensitive value(s): ${[...new Set(found.map((f) => f.detector))].join(', ')}.`,
        evidence: found.slice(0, 3).map(maskValue).join(', '),
      },
    ];
  },
};

export const sensitiveEgress: Rule = {
  id: 'AX-DLP-002',
  title: 'Sensitive data in outbound action',
  stage: 'action',
  severity: 'critical',
  defaultAction: 'block',
  locked: true,
  description:
    'Sensitive values in an action target or payload, including percent-encoded and base64-encoded URL components. Always blocks: redacting a side effect silently changes its meaning.',
  evaluate(ctx) {
    const hits: RuleHit[] = [];
    (ctx.request.actions ?? []).forEach((a, i) => {
      const found = dedupe(actionSurfaces(a).flatMap((s) => scanSensitive(normalizeForMatching(s), ctx.policy.dlp.detectors)));
      if (found.length === 0) return;
      hits.push({
        target: `action:${i}`,
        message: `${a.kind} action carries sensitive data: ${[...new Set(found.map((f) => f.detector))].join(', ')}.`,
        evidence: found.slice(0, 3).map(maskValue).join(', '),
      });
    });
    return hits;
  },
};

function dedupe(matches: DlpMatch[]): DlpMatch[] {
  const seen = new Set<string>();
  return matches.filter((m) => {
    const key = `${m.detector}:${m.value.replace(/\D/g, '') || m.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
