import { Axiom, type AxiomOptions } from '../src/index.js';
import type { EvaluateRequest } from '../src/types.js';

export function axiom(policy: AxiomOptions['policy'] = {}, extra: Omit<AxiomOptions, 'policy'> = {}): Axiom {
  let n = 0;
  return new Axiom({ policy, clock: () => new Date('2026-01-01T00:00:00Z'), idGenerator: () => `evt-${n++}`, ...extra });
}

export function req(partial: Partial<EvaluateRequest> = {}): EvaluateRequest {
  return { tenantId: 't1', principal: { roles: [], clearance: 'internal' }, ...partial };
}

export const ruleIds = (r: { findings: Array<{ ruleId: string }> }) => [...new Set(r.findings.map((f) => f.ruleId))];

/** Builds strings with invisible characters without putting them in source. */
export const cp = (...points: number[]) => String.fromCodePoint(...points);
export const tagEncode = (s: string) => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join('');
