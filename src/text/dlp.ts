/**
 * Deterministic sensitive-data detectors. Each detector validates structure
 * (Luhn for cards, SSA rules for SSNs, mod-97 for IBANs) to keep false
 * positives low enough that blocking on a match is reasonable.
 */

import type { DlpDetectorId } from '../policy.js';

export interface DlpMatch {
  detector: DlpDetectorId;
  value: string;
  index: number;
}

interface Detector {
  id: DlpDetectorId;
  pattern: RegExp;
  validate?: (match: string) => boolean;
}

const DETECTORS: Detector[] = [
  {
    id: 'ssn',
    // Area 000, 666 and 900-999 are never issued; group 00 and serial 0000 are invalid.
    pattern: /(?<!\d)(?!000|666|9\d\d)\d{3}([- ])(?!00)\d{2}\1(?!0000)\d{4}(?!\d)/g,
  },
  {
    id: 'credit_card',
    pattern: /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
    validate: (m) => {
      const digits = m.replace(/\D/g, '');
      return digits.length >= 13 && digits.length <= 19 && luhn(digits) && /^[3-6]/.test(digits);
    },
  },
  // No boundaries: the prefix is distinctive enough, and gluing a key to other text must not hide it.
  { id: 'aws_access_key', pattern: /(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}/g },
  { id: 'private_key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g },
  { id: 'github_token', pattern: /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})(?![A-Za-z0-9_])/g },
  { id: 'slack_token', pattern: /(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}/g },
  { id: 'jwt', pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { id: 'email_address', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  {
    id: 'iban',
    pattern: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g,
    validate: (m) => ibanValid(m.replace(/ /g, '')),
  },
];

export function scanSensitive(text: string, enabled: readonly DlpDetectorId[]): DlpMatch[] {
  const out: DlpMatch[] = [];
  for (const d of DETECTORS) {
    if (!enabled.includes(d.id)) continue;
    for (const m of text.matchAll(d.pattern)) {
      if (d.validate && !d.validate(m[0])) continue;
      out.push({ detector: d.id, value: m[0], index: m.index });
    }
  }
  return out;
}

export function redactSensitive(text: string, enabled: readonly DlpDetectorId[]): { text: string; count: number } {
  let count = 0;
  let t = text;
  for (const d of DETECTORS) {
    if (!enabled.includes(d.id)) continue;
    t = t.replace(d.pattern, (m) => {
      if (d.validate && !d.validate(m)) return m;
      count++;
      return `[REDACTED:${d.id}]`;
    });
  }
  return { text: t, count };
}

/** Masks a sensitive value for evidence fields: keeps the detector name and last 2 chars. */
export function maskValue(match: DlpMatch): string {
  return `${match.detector}(…${match.value.slice(-2)})`;
}

export function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function ibanValid(iban: string): boolean {
  if (iban.length < 15 || iban.length > 34) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const digit of v) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}
