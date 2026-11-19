import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AuditLog, JsonlAuditSink, verifyChain } from '../src/index.js';
import { axiom, req } from './helpers.js';

const dir = () => mkdtempSync(join(tmpdir(), 'axiom-'));

describe('JSONL audit log', () => {
  it('persists events and resumes the chain across restarts', () => {
    const file = join(dir(), 'audit.jsonl');
    const first = axiom({}, { audit: AuditLog.resume(new JsonlAuditSink(file)) });
    first.evaluate(req({ input: 'a' }));
    first.evaluate(req({ output: '<img src=x>' }));

    // Simulate a restart: a new process resumes from the file.
    const second = axiom({}, { audit: AuditLog.resume(new JsonlAuditSink(file)) });
    second.evaluate(req({ input: 'b' }));

    const events = new JsonlAuditSink(file).readAll();
    expect(events.map((e) => e.seq)).toEqual([0, 1, 2]);
    expect(events[2]!.prevHash).toBe(events[1]!.hash);
    expect(verifyChain(events).ok).toBe(true);
  });

  it('refuses to append to a tampered log', () => {
    const file = join(dir(), 'audit.jsonl');
    const ax = axiom({}, { audit: AuditLog.resume(new JsonlAuditSink(file)) });
    ax.evaluate(req({ output: '<img src=x>' }));
    ax.evaluate(req({ input: 'ok' }));
    writeFileSync(file, readFileSync(file, 'utf8').replace('"decision":"block"', '"decision":"allow"'));
    expect(() => AuditLog.resume(new JsonlAuditSink(file))).toThrow(/corrupted/);
  });

  it('detects removal of the oldest events, and verifies anchored segments', () => {
    const file = join(dir(), 'audit.jsonl');
    const ax = axiom({}, { audit: AuditLog.resume(new JsonlAuditSink(file)) });
    for (const i of [1, 2, 3, 4]) ax.evaluate(req({ input: `q${i}` }));
    const events = new JsonlAuditSink(file).readAll();
    expect(verifyChain(events.slice(1))).toMatchObject({ ok: false, brokenAt: 0 });
    // A rotated segment verifies against the last event of the previous segment.
    const anchor = { seq: events[1]!.seq!, hash: events[1]!.hash! };
    expect(verifyChain(events.slice(2), { anchor }).ok).toBe(true);
    expect(verifyChain(events.slice(3), { anchor }).ok).toBe(false);
  });

  it('reads a missing file as empty', () => {
    expect(new JsonlAuditSink(join(dir(), 'none.jsonl')).readAll()).toEqual([]);
  });
});

describe('CLI', () => {
  const cli = (args: string[]) => {
    try {
      return { code: 0, out: execFileSync('npx', ['tsx', 'src/cli.ts', ...args], { encoding: 'utf8' }) };
    } catch (e) {
      const err = e as { status: number; stdout: string; stderr: string };
      return { code: err.status, out: err.stdout + err.stderr };
    }
  };

  it('check exits 2 on block and prints findings', () => {
    const r = cli(['check', 'examples/request.json', '--policy', 'examples/policy.yaml']);
    expect(r.code).toBe(2);
    expect(r.out).toContain('decision: BLOCK');
    expect(r.out).toContain('AX-ACT-003');
  });

  it('audit verify detects tampering', () => {
    const file = join(dir(), 'audit.jsonl');
    const ax = axiom({}, { audit: AuditLog.resume(new JsonlAuditSink(file)) });
    ax.evaluate(req({ input: 'x' }));
    ax.evaluate(req({ input: 'y' }));
    expect(cli(['audit', 'verify', file])).toMatchObject({ code: 0 });
    writeFileSync(file, readFileSync(file, 'utf8').split('\n').slice(1).join('\n'));
    const broken = cli(['audit', 'verify', file]);
    expect(broken.code).toBe(1);
    expect(broken.out).toContain('BROKEN');
  });

  it('harness runs a custom policy and scenario set', () => {
    const r = cli(['harness', '--policy', 'policies/default.yaml', '--json']);
    const summary = JSON.parse(r.out.slice(r.out.indexOf('{'))) as { policy: string; total: number };
    expect(summary.policy).toBe('default');
    expect(summary.total).toBeGreaterThan(60);
  });

  it('rejects unknown commands', () => {
    expect(cli(['nope']).code).toBe(1);
  });
}, 30_000);
