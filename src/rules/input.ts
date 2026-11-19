import { inspectHidden } from '../text/normalize.js';
import { DIRECT_PATTERNS, matchPatterns } from './patterns.js';
import { excerpt, type Rule, type RuleHit } from './rule.js';

export const instructionOverride: Rule = {
  id: 'AX-INP-001',
  title: 'Instruction override attempt in user input',
  stage: 'input',
  severity: 'medium',
  defaultAction: 'escalate',
  description:
    'Heuristic detection of direct prompt injection and jailbreak phrasing in the user message. A signal for review and rate limiting, not a security boundary.',
  evaluate(ctx) {
    const text = ctx.normalized.input;
    if (!text) return [];
    const hits = matchPatterns(text, DIRECT_PATTERNS);
    if (hits.length === 0) return [];
    return [
      {
        target: 'input',
        message: `Instruction override phrasing detected (${hits.map((h) => h.id).join(', ')}).`,
        evidence: excerpt(hits[0]!.match),
      },
    ];
  },
};

export const hiddenUnicode: Rule = {
  id: 'AX-INP-002',
  title: 'Invisible or smuggled Unicode',
  stage: 'input',
  severity: 'high',
  defaultAction: 'sanitize',
  description:
    'Zero-width, bidirectional-override and Unicode tag characters are stripped before content reaches the model or user. Tag characters carrying hidden ASCII ("ASCII smuggling") escalate.',
  evaluate(ctx) {
    const hits: RuleHit[] = [];
    const surfaces: Array<[string, string | undefined]> = [
      ['input', ctx.request.input],
      ['output', ctx.request.output],
      ...(ctx.request.context ?? []).map((c): [string, string | undefined] => [`context:${c.id}`, c.content]),
    ];
    for (const [target, text] of surfaces) {
      if (!text) continue;
      const r = inspectHidden(text);
      if (r.tags > 0) {
        hits.push({
          target,
          action: 'escalate',
          message: `${r.tags} invisible Unicode tag characters found; they decode to hidden text.`,
          evidence: excerpt(r.smuggled, 60),
        });
      } else if (r.bidi > 0 || r.zeroWidth > 0) {
        hits.push({ target, message: `Stripped ${r.zeroWidth} zero-width and ${r.bidi} bidi control characters.` });
      }
    }
    return hits;
  },
};
