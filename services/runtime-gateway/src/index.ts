import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { z } from 'zod';
import { evaluatePolicy } from './policy.js';

const app = new Hono();

const SinkSchema = z.object({
  type: z.enum(['url', 'webhook', 'email', 'export', 'memory', 'tool']),
  url: z.string().optional(),
  destination: z.string().optional(),
  args: z.record(z.unknown()).optional(),
});

const ChunkSchema = z.object({
  chunkId: z.string(),
  tenantId: z.string(),
  trustClass: z.enum(['trusted', 'internal', 'untrusted', 'generated']),
  sensitivity: z.enum(['public', 'internal', 'pii', 'npi']),
  allowedRoles: z.array(z.string()).optional(),
});

const EvaluateSchema = z.object({
  tenantId: z.string(),
  userId: z.string().optional(),
  sessionId: z.string().optional(),
  role: z.string().optional(),
  channel: z.enum(['chat', 'rag', 'agent', 'api']),
  input: z.string(),
  retrievedChunks: z.array(ChunkSchema).default([]),
  proposedOutput: z.string().optional(),
  proposedSinks: z.array(SinkSchema).default([]),
});

app.get('/health', (c) => c.json({ ok: true, service: 'axiom-runtime-gateway' }));

app.post('/v1/evaluate', async (c) => {
  const body = await c.req.json().catch(() => null);
  const parsed = EvaluateSchema.safeParse(body);
  if (!parsed.success) {
    return c.json({ error: 'invalid_request', details: parsed.error.flatten() }, 400);
  }
  return c.json(evaluatePolicy(parsed.data));
});

const port = Number(process.env.PORT ?? 8787);
serve({ fetch: app.fetch, port });
console.log(`Axiom runtime gateway listening on :${port}`);
