/** Regenerates JSON Schemas in `schemas/` from the Zod definitions, so they never drift. */
import { mkdirSync, writeFileSync } from 'node:fs';
import { z } from 'zod';
import { PolicySchema } from '../src/policy.js';
import { EvaluateRequestSchema } from '../src/schema.js';

mkdirSync('schemas', { recursive: true });
const emit = (name: string, schema: z.ZodType) =>
  writeFileSync(`schemas/${name}.schema.json`, `${JSON.stringify(z.toJSONSchema(schema, { io: 'input' }), null, 2)}\n`);
emit('policy', PolicySchema);
emit('evaluate-request', EvaluateRequestSchema);
console.log('wrote schemas/policy.schema.json, schemas/evaluate-request.schema.json');
