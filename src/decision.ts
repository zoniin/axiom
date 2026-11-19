import type { Decision, Sensitivity } from './types.js';

const DECISION_RANK: Record<Decision, number> = {
  allow: 0,
  sanitize: 1,
  escalate: 2,
  block: 3,
};

/** Returns the more restrictive of two decisions. */
export function stricter(a: Decision, b: Decision): Decision {
  return DECISION_RANK[a] >= DECISION_RANK[b] ? a : b;
}

/** Folds a list of decisions to the most restrictive one. Empty list means `allow`. */
export function reduceDecisions(decisions: Iterable<Decision>): Decision {
  let result: Decision = 'allow';
  for (const d of decisions) result = stricter(result, d);
  return result;
}

export function decisionRank(d: Decision): number {
  return DECISION_RANK[d];
}

const SENSITIVITY_RANK: Record<Sensitivity, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
};

export function sensitivityRank(s: Sensitivity): number {
  return SENSITIVITY_RANK[s];
}
