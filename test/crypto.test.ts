import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { sha256Hex } from '../src/crypto/sha256.js';

const node = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

describe('sha256Hex', () => {
  it('matches the NIST test vectors', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
  it('matches node:crypto across block boundaries and multi-byte text', () => {
    for (let n = 0; n < 200; n++) {
      const s = 'é🔒a'.repeat(n).slice(0, n);
      expect(sha256Hex(s)).toBe(node(s));
    }
    const big = 'x'.repeat(100_000);
    expect(sha256Hex(big)).toBe(node(big));
  });
});
