import { describe, expect, it } from 'vitest';
import { runHarness } from '../src/harness.js';

describe('red-team harness', () => {
  const summary = runHarness();
  it('loads a meaningful corpus', () => {
    expect(summary.total).toBeGreaterThanOrEqual(60);
  });
  it.each(summary.results.map((r) => [r.id, r] as const))('%s', (_id, r) => {
    expect(r.problems).toEqual([]);
  });
  it('has no benign false positives', () => {
    expect(summary.benign.falsePositives).toBe(0);
  });
  it('contains every attack scenario', () => {
    expect(summary.attack.contained).toBe(summary.attack.total);
  });
});
