import { unsupportedCommitment } from './commitments.js';
import { hiddenUnicode, instructionOverride } from './input.js';
import { canaryLeak, sensitiveEgress, sensitiveOutput } from './leakage.js';
import { activeContent, untrustedLinks } from './rendering.js';
import { accessAuthorization, indirectInjection, tenantIsolation } from './retrieval.js';
import type { Rule } from './rule.js';
import { sinkDefaultDeny, taintedAction, untrustedDestination } from './sinks.js';

export type { Rule, RuleContext, RuleHit } from './rule.js';
export { evaluateSink } from './sinks.js';
export { COMMITMENT_PACKS } from './commitments.js';

/** Context-authorization rules run first; their drops define what every later rule sees. */
export const AUTHORIZATION_RULES: readonly Rule[] = [tenantIsolation, accessAuthorization];

export const CONTENT_RULES: readonly Rule[] = [
  instructionOverride,
  hiddenUnicode,
  indirectInjection,
  activeContent,
  untrustedLinks,
  canaryLeak,
  sensitiveOutput,
  unsupportedCommitment,
  sinkDefaultDeny,
  taintedAction,
  untrustedDestination,
  sensitiveEgress,
];

export const BUILTIN_RULES: readonly Rule[] = [...AUTHORIZATION_RULES, ...CONTENT_RULES];

/** Rule IDs reserved for the engine itself. */
export const SYSTEM_RULES = {
  internalError: 'AX-SYS-001',
  detectorSignal: 'AX-SYS-002',
  invalidOverride: 'AX-SYS-003',
} as const;
