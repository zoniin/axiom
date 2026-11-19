import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * Policy configuration. Every field has a safe default, so `{}` is a valid,
 * maximally restrictive policy: no outbound sinks, no images, no external links.
 */

const DecisionSchema = z.enum(['allow', 'sanitize', 'escalate', 'block']);

/** `api.example.com` matches exactly; `*.example.com` matches any subdomain (not the apex). */
const HostPattern = z
  .string()
  .min(1)
  .transform((s) => s.trim().toLowerCase())
  .refine((s) => /^(\*\.)?[a-z0-9.-]+$/.test(s) && !s.includes('..'), {
    message: 'host must be a hostname or *.hostname wildcard',
  });

const HttpAllowEntry = z.object({
  host: HostPattern,
  /** Allowed HTTP methods. Defaults to GET and POST. */
  methods: z.array(z.string().transform((m) => m.toUpperCase())).default(['GET', 'POST']),
  /** Optional path prefix, e.g. `/v1/webhooks/`. */
  pathPrefix: z.string().startsWith('/').optional(),
});

const SinkMode = z.enum(['deny', 'escalate', 'allow']);

export const DLP_DETECTORS = [
  'ssn',
  'credit_card',
  'aws_access_key',
  'private_key',
  'github_token',
  'slack_token',
  'jwt',
  'email_address',
  'iban',
] as const;
export type DlpDetectorId = (typeof DLP_DETECTORS)[number];

export const PolicySchema = z.object({
  version: z.literal(1).default(1),
  name: z.string().default('default'),

  sinks: z
    .object({
      http: z.object({ allow: z.array(HttpAllowEntry).default([]) }).default({ allow: [] }),
      email: z.object({ allowDomains: z.array(HostPattern).default([]) }).default({ allowDomains: [] }),
      tools: z
        .object({
          /** Tools that may run with no extra checks beyond taint and DLP. */
          allow: z.array(z.string()).default([]),
          /** Tools that always require human approval. */
          escalate: z.array(z.string()).default([]),
        })
        .default({ allow: [], escalate: [] }),
      memory: SinkMode.default('escalate'),
      export: SinkMode.default('deny'),
    })
    .default({
      http: { allow: [] },
      email: { allowDomains: [] },
      tools: { allow: [], escalate: [] },
      memory: 'escalate',
      export: 'deny',
    }),

  rendering: z
    .object({
      /** What to do with markdown/HTML images, active HTML and dangerous URI schemes. */
      activeContent: z.enum(['block', 'sanitize']).default('block'),
      /** Hosts that output links may point to. Anything else is defanged. */
      linkAllowHosts: z.array(HostPattern).default([]),
    })
    .default({ activeContent: 'block', linkAllowHosts: [] }),

  dlp: z
    .object({
      detectors: z.array(z.enum(DLP_DETECTORS)).default(['ssn', 'credit_card', 'aws_access_key', 'private_key', 'github_token', 'slack_token', 'jwt']),
      /** Sensitive data in model output: redact (`sanitize`) or `block`. */
      output: z.enum(['sanitize', 'block']).default('sanitize'),
    })
    .default({
      detectors: ['ssn', 'credit_card', 'aws_access_key', 'private_key', 'github_token', 'slack_token', 'jwt'],
      output: 'sanitize',
    }),

  /** Secret strings planted in system prompts. Seeing one in output proves a prompt leak. */
  canaries: z.array(z.string().min(8)).default([]),

  commitments: z
    .object({
      /** Built-in phrase packs. See `rules/commitments.ts`. */
      packs: z.array(z.enum(['finance', 'legal', 'healthcare'])).default([]),
      /** Extra case-insensitive regular expressions. */
      patterns: z.array(z.string()).default([]),
    })
    .default({ packs: [], patterns: [] }),

  /** Per-rule action overrides. Locked rules cannot be weakened. */
  overrides: z.record(z.string(), DecisionSchema).default({}),

  detectors: z
    .object({
      /** Optional model-based detectors. Off by default; never the sole boundary. */
      timeoutMs: z.number().int().positive().max(5000).default(250),
      enabled: z.array(z.string()).default([]),
    })
    .default({ timeoutMs: 250, enabled: [] }),
});

export type PolicyInput = z.input<typeof PolicySchema>;
export type Policy = z.output<typeof PolicySchema>;

export function parsePolicy(input: unknown): Policy {
  return PolicySchema.parse(input ?? {});
}

export function loadPolicyFile(path: string): Policy {
  const raw = readFileSync(path, 'utf8');
  const data = path.endsWith('.json') ? JSON.parse(raw) : parseYaml(raw);
  return parsePolicy(data);
}

/** Stable SHA-256 of the effective policy, recorded in every audit event. */
export function policyHash(policy: Policy): string {
  return createHash('sha256').update(canonicalJson(policy)).digest('hex');
}

/** JSON with sorted keys, so hashes don't depend on property order. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}
