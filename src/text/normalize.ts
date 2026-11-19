/**
 * Text normalization used before any pattern matching.
 *
 * Attackers routinely evade naive filters with zero-width characters, fullwidth
 * forms, Cyrillic lookalikes and invisible Unicode "tag" characters (so-called
 * ASCII smuggling). Rules match against `normalizeForMatching(text)`, never raw text.
 */

// U+200D (zero-width joiner) is deliberately excluded: emoji sequences depend on it.
const ZERO_WIDTH = /[\u200B\u200C\u2060-\u2064\uFEFF\u00AD\u180E]/g;
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;
// Unicode tag block U+E0000..U+E007F. Mirrors ASCII and renders invisibly.
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;
const TAG_CHARS_TEST = /[\u{E0000}-\u{E007F}]/u;

/** Small confusables map covering the lookalikes most often used to dodge keyword filters. */
const CONFUSABLES: Record<string, string> = {
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  х: 'x',
  і: 'i',
  ј: 'j',
  ѕ: 's',
  һ: 'h',
  ԁ: 'd',
  ɡ: 'g',
  А: 'A',
  В: 'B',
  Е: 'E',
  К: 'K',
  М: 'M',
  Н: 'H',
  О: 'O',
  Р: 'P',
  С: 'C',
  Т: 'T',
  Х: 'X',
  І: 'I',
  α: 'a',
  ο: 'o',
  ν: 'v',
  ι: 'i',
  κ: 'k',
  τ: 't',
  ρ: 'p',
  Α: 'A',
  Β: 'B',
  Ε: 'E',
  Η: 'H',
  Ι: 'I',
  Κ: 'K',
  Μ: 'M',
  Ν: 'N',
  Ο: 'O',
  Ρ: 'P',
  Τ: 'T',
  Χ: 'X',
  Υ: 'Y',
  Ζ: 'Z',
};
const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join('')}]`, 'g');

export interface HiddenCharReport {
  zeroWidth: number;
  bidi: number;
  tags: number;
  /** ASCII text recovered from tag characters, if any. */
  smuggled: string;
}

export function inspectHidden(text: string): HiddenCharReport {
  return {
    zeroWidth: countMatches(text, ZERO_WIDTH),
    bidi: countMatches(text, BIDI_CONTROLS),
    tags: countMatches(text, TAG_CHARS),
    smuggled: decodeTagChars(text),
  };
}

export function hasHidden(text: string): boolean {
  ZERO_WIDTH.lastIndex = 0;
  BIDI_CONTROLS.lastIndex = 0;
  return ZERO_WIDTH.test(text) || BIDI_CONTROLS.test(text) || TAG_CHARS_TEST.test(text);
}

/** Recovers the ASCII payload hidden in Unicode tag characters. */
export function decodeTagChars(text: string): string {
  let out = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

/** Removes invisible characters. Used when rendering content for the model or user. */
export function stripHidden(text: string): string {
  return text.replace(ZERO_WIDTH, '').replace(BIDI_CONTROLS, '').replace(TAG_CHARS, '');
}

/**
 * Canonical form for pattern matching: NFKC, invisible characters removed,
 * confusables folded to ASCII, whitespace collapsed. Smuggled tag-character
 * text is appended so rules see it too.
 */
export function normalizeForMatching(text: string): string {
  const smuggled = decodeTagChars(text);
  let t = stripHidden(text).normalize('NFKC');
  t = t.replace(CONFUSABLE_RE, (c) => CONFUSABLES[c] ?? c);
  t = t.replace(/\s+/g, ' ').trim();
  return smuggled ? `${t} ${smuggled}` : t;
}

function countMatches(text: string, re: RegExp): number {
  const global = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  return text.match(global)?.length ?? 0;
}
