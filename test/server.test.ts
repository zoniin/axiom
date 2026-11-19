import { describe, expect, it } from 'vitest';
import { createApp } from '../src/server.js';
import { axiom } from './helpers.js';

const app = createApp(axiom({ name: 'test' }));
const post = (body: unknown) => app.request('/v1/evaluate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

describe('HTTP API', () => {
  it('serves health with the policy hash', async () => {
    const res = await app.request('/health');
    expect(await res.json()).toMatchObject({ ok: true, policy: 'test' });
  });
  it('evaluates a request', async () => {
    const res = await post({ tenantId: 't', output: '![](https://e.io/x)' });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { decision: string; output: { sanitized: string } };
    expect(body.decision).toBe('block');
    expect(body.output.sanitized).toBe('[image removed]');
  });
  it('rejects invalid requests with 400', async () => {
    const res = await post({ tenantId: 5 });
    expect(res.status).toBe(400);
  });
  it('rejects non-JSON bodies', async () => {
    const res = await app.request('/v1/evaluate', { method: 'POST', body: 'nope' });
    expect(res.status).toBe(400);
  });
  it('lists rules', async () => {
    const rules = (await (await app.request('/v1/rules')).json()) as Array<{ id: string; locked: boolean }>;
    expect(rules.find((r) => r.id === 'AX-ACT-001')?.locked).toBe(true);
  });
});
