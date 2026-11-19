import { excerpt, type Rule } from './rule.js';

/**
 * Phrase packs for claims a model must not make on a company's behalf.
 * These are domain examples; extend with `commitments.patterns` in policy.
 */
export const COMMITMENT_PACKS: Record<'finance' | 'legal' | 'healthcare', RegExp[]> = {
  finance: [
    /\bguaranteed? (loan |credit )?approval\b/i,
    /\byou (are|have been|'re) (pre-?)?approved for\b/i,
    /\b(we|i) (can |will )?guarantee (you )?(an? |the |your )?(apr|rate|interest rate|approval|loan)\b/i,
    /\b(we|i) (will|can|'ll) waive (your |the )?[a-z ]{0,20}fees?\b/i,
    /\byour (loan|application|credit line) (has been|is|was) (approved|denied|declined)\b/i,
    /\bthe (reason|basis) for (your |the )?(denial|decline|adverse action) (is|was)\b/i,
    /\b(lock(ed)?|locking) in your rate\b/i,
    /\brisk[- ]free (investment|return)s?\b|\bguaranteed returns?\b/i,
  ],
  legal: [
    /\bthis (constitutes|is) (formal )?legal advice\b/i,
    /\b(this|that) (is|will be) legally binding\b/i,
    /\byou (will|cannot|can't) (definitely )?(win|lose) (the|this|your) case\b/i,
    /\bi am (acting as )?your (attorney|lawyer|counsel)\b/i,
  ],
  healthcare: [
    /\byou (definitely|certainly|clearly) have\b/i,
    /\byou should (stop|discontinue) taking\b/i,
    /\b(no need|you don'?t need) to (see|consult) a (doctor|physician)\b/i,
    /\bthis is (a |your )?(medical )?diagnosis\b/i,
  ],
};

export const unsupportedCommitment: Rule = {
  id: 'AX-OUT-004',
  title: 'Unsupported commitment in output',
  stage: 'output',
  severity: 'high',
  defaultAction: 'escalate',
  description:
    'The model makes a binding-sounding promise in a regulated domain (approvals, rates, fee waivers, legal or medical conclusions). Enable packs with `commitments.packs`.',
  evaluate(ctx) {
    const text = ctx.normalized.output;
    if (!text) return [];
    const patterns = [
      ...ctx.policy.commitments.packs.flatMap((p) => COMMITMENT_PACKS[p]),
      ...ctx.policy.commitments.patterns.map((p) => new RegExp(p, 'i')),
    ];
    for (const re of patterns) {
      const m = re.exec(text);
      if (m) return [{ target: 'output', message: 'Output makes a commitment that requires human review.', evidence: excerpt(m[0]) }];
    }
    return [];
  },
};
