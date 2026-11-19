import { z } from 'zod';

/**
 * Zod schemas for the public API boundary. The HTTP server and the library
 * entry point both validate with these, so malformed requests never reach rules.
 */

const MAX_TEXT = 200_000;

export const SensitivitySchema = z.enum(['public', 'internal', 'confidential', 'restricted']);
export const TrustSchema = z.enum(['trusted', 'internal', 'untrusted']);

export const PrincipalSchema = z.object({
  userId: z.string().max(256).optional(),
  roles: z.array(z.string().max(128)).max(64).default([]),
  clearance: SensitivitySchema.default('internal'),
});

export const ContextChunkSchema = z.object({
  id: z.string().min(1).max(256),
  tenantId: z.string().min(1).max(256),
  source: z.string().max(512).optional(),
  trust: TrustSchema,
  sensitivity: SensitivitySchema.default('internal'),
  allowedRoles: z.array(z.string().max(128)).max(64).optional(),
  content: z.string().max(MAX_TEXT).optional(),
  declassifiedBy: z.string().max(256).optional(),
});

export const ProposedActionSchema = z.object({
  kind: z.enum(['http', 'email', 'tool', 'memory', 'export']),
  target: z.string().min(1).max(4096),
  method: z.string().max(16).optional(),
  payload: z.unknown().optional(),
});

export const EvaluateRequestSchema = z.object({
  tenantId: z.string().min(1).max(256),
  sessionId: z.string().max(256).optional(),
  principal: PrincipalSchema.default({ roles: [], clearance: 'internal' }),
  input: z.string().max(MAX_TEXT).optional(),
  context: z.array(ContextChunkSchema).max(500).optional(),
  output: z.string().max(MAX_TEXT).optional(),
  actions: z.array(ProposedActionSchema).max(100).optional(),
});

export type EvaluateRequestInput = z.input<typeof EvaluateRequestSchema>;
