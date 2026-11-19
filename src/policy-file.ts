import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { type Policy, parsePolicy } from './policy.js';

/** Node-only: loads a YAML or JSON policy file. */
export function loadPolicyFile(path: string): Policy {
  const raw = readFileSync(path, 'utf8');
  const data: unknown = path.endsWith('.json') ? JSON.parse(raw) : parseYaml(raw);
  return parsePolicy(data);
}
