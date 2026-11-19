import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { z } from 'zod';
import type { Axiom } from './engine.js';
import { EvaluateRequestSchema } from './schema.js';
import type { EvaluateRequest } from './types.js';

/**
 * HTTP gateway. Stateless apart from the audit log, so it scales horizontally
 * behind any load balancer. Mount it in-VPC next to the application.
 */
export function createApp(axiom: Axiom): Hono {
  const app = new Hono();

  app.use('/v1/*', bodyLimit({ maxSize: 2 * 1024 * 1024, onError: (c) => c.json({ error: 'payload_too_large' }, 413) }));

  app.get('/health', (c) => c.json({ ok: true, service: 'axiom', policy: axiom.policy.name, policyHash: axiom.policyHash }));

  app.get('/v1/rules', (c) =>
    c.json(
      axiom.rules.map((r) => ({
        id: r.id,
        title: r.title,
        stage: r.stage,
        severity: r.severity,
        defaultAction: r.defaultAction,
        effectiveAction: axiom.policy.overrides[r.id] ?? r.defaultAction,
        locked: r.locked ?? false,
        description: r.description,
      })),
    ),
  );

  app.get('/v1/policy', (c) => c.json({ hash: axiom.policyHash, policy: axiom.policy }));

  app.post('/v1/evaluate', async (c) => {
    const body: unknown = await c.req.json().catch(() => undefined);
    const parsed = EvaluateRequestSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: 'invalid_request', issues: z.treeifyError(parsed.error) }, 400);
    try {
      const result = await axiom.evaluateWithDetectors(parsed.data as EvaluateRequest);
      return c.json(result);
    } catch (err) {
      // Fail closed: an engine error is a block, never an allow.
      console.error('axiom: evaluation failed', err);
      return c.json({ decision: 'block', error: 'evaluation_failed' }, 500);
    }
  });

  return app;
}
