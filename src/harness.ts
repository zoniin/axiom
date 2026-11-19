import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { Axiom } from './engine.js';
import { loadPolicyFile } from './policy-file.js';
import { EvaluateRequestSchema } from './schema.js';
import type { Decision, EvaluateRequest } from './types.js';

/**
 * Red-team harness. Runs every scenario in `harness/scenarios/*.yaml` through
 * the real engine and measures two things that must be reported together:
 * attack containment and benign utility. A guard that blocks everything is
 * 100% secure and 0% useful.
 */

const Decision = z.enum(['allow', 'sanitize', 'escalate', 'block']);

const ScenarioSchema = z.object({
  id: z.string(),
  kind: z.enum(['attack', 'benign', 'known_gap']),
  category: z.string(),
  description: z.string(),
  /** Reference to public research or a real incident class. */
  reference: z.string().optional(),
  request: EvaluateRequestSchema,
  expect: z.object({
    decision: Decision,
    rules: z.array(z.string()).default([]),
    notRules: z.array(z.string()).default([]),
    dropped: z.array(z.string()).default([]),
    /** Strings that must not survive into the sanitized output. */
    outputExcludes: z.array(z.string()).default([]),
  }),
});

const FileSchema = z.object({ scenarios: z.array(ScenarioSchema) });

export type Scenario = z.infer<typeof ScenarioSchema>;

export interface ScenarioResult {
  id: string;
  kind: Scenario['kind'];
  category: string;
  description: string;
  expected: Decision;
  got: Decision;
  rules: string[];
  passed: boolean;
  problems: string[];
}

export interface HarnessSummary {
  policy: string;
  policyHash: string;
  total: number;
  results: ScenarioResult[];
  failed: ScenarioResult[];
  attack: { total: number; contained: number };
  benign: { total: number; passedThrough: number; falsePositives: number };
  knownGaps: number;
}

const HERE = dirname(fileURLToPath(import.meta.url));
export const HARNESS_DIR = resolve(HERE, '..', 'harness');

export function loadScenarios(dir = join(HARNESS_DIR, 'scenarios')): Scenario[] {
  const files = readdirSync(dir).filter((f) => f.endsWith('.yaml')).sort();
  const all: Scenario[] = [];
  for (const f of files) {
    const parsed = FileSchema.safeParse(parseYaml(readFileSync(join(dir, f), 'utf8')));
    if (!parsed.success) throw new Error(`${f}: ${parsed.error.message}`);
    all.push(...parsed.data.scenarios);
  }
  const ids = new Set<string>();
  for (const s of all) {
    if (ids.has(s.id)) throw new Error(`duplicate scenario id ${s.id}`);
    ids.add(s.id);
  }
  return all;
}

export function runHarness(options: { scenarios?: Scenario[]; policyFile?: string } = {}): HarnessSummary {
  const policy = loadPolicyFile(options.policyFile ?? join(HARNESS_DIR, 'policy.yaml'));
  const axiom = new Axiom({ policy, clock: () => new Date(0), idGenerator: () => 'harness' });
  const scenarios = options.scenarios ?? loadScenarios();

  const results = scenarios.map((s): ScenarioResult => {
    const r = axiom.evaluate(s.request as EvaluateRequest);
    const rules = [...new Set(r.findings.map((f) => f.ruleId))];
    const problems: string[] = [];
    if (r.decision !== s.expect.decision) problems.push(`decision ${r.decision}, expected ${s.expect.decision}`);
    for (const id of s.expect.rules) if (!rules.includes(id)) problems.push(`expected rule ${id} to fire`);
    for (const id of s.expect.notRules) if (rules.includes(id)) problems.push(`rule ${id} fired unexpectedly`);
    for (const id of s.expect.dropped) if (!r.context.dropped.some((d) => d.id === id)) problems.push(`expected chunk ${id} to be dropped`);
    for (const needle of s.expect.outputExcludes) {
      if (r.output?.sanitized.includes(needle)) problems.push(`sanitized output still contains "${needle}"`);
    }
    return {
      id: s.id,
      kind: s.kind,
      category: s.category,
      description: s.description,
      expected: s.expect.decision,
      got: r.decision,
      rules,
      passed: problems.length === 0,
      problems,
    };
  });

  const attacks = results.filter((r) => r.kind === 'attack');
  const benign = results.filter((r) => r.kind === 'benign');
  return {
    policy: axiom.policy.name,
    policyHash: axiom.policyHash,
    total: results.length,
    results,
    failed: results.filter((r) => !r.passed),
    attack: { total: attacks.length, contained: attacks.filter((r) => r.got !== 'allow').length },
    benign: {
      total: benign.length,
      passedThrough: benign.filter((r) => r.got === 'allow' || r.got === 'sanitize').length,
      falsePositives: benign.filter((r) => r.got === 'escalate' || r.got === 'block').length,
    },
    knownGaps: results.filter((r) => r.kind === 'known_gap').length,
  };
}

const pct = (n: number, d: number) => (d === 0 ? 'n/a' : `${((100 * n) / d).toFixed(1)}%`);

export function renderReport(s: HarnessSummary, opts: { color?: boolean } = {}): string {
  const mark = (ok: boolean) => (opts.color ? (ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m') : ok ? 'PASS' : 'FAIL');
  const lines: string[] = [];
  lines.push('# Axiom harness report', '');
  lines.push(`Policy \`${s.policy}\` (\`${s.policyHash.slice(0, 12)}\`), ${s.total} scenarios.`, '');
  lines.push('| Metric | Value |', '|---|---|');
  lines.push(`| Attack scenarios contained (not allowed) | ${s.attack.contained}/${s.attack.total} (${pct(s.attack.contained, s.attack.total)}) |`);
  lines.push(`| Benign scenarios passed through (allow or sanitize) | ${s.benign.passedThrough}/${s.benign.total} (${pct(s.benign.passedThrough, s.benign.total)}) |`);
  lines.push(`| Benign false positives (escalate or block) | ${s.benign.falsePositives} |`);
  lines.push(`| Documented known gaps | ${s.knownGaps} |`);
  lines.push(`| Scenarios matching expectations exactly | ${s.total - s.failed.length}/${s.total} |`, '');

  const categories = [...new Set(s.results.map((r) => r.category))].sort();
  lines.push('## By category', '', '| Category | Attacks contained | Benign passed | Exact |', '|---|---|---|---|');
  for (const c of categories) {
    const rs = s.results.filter((r) => r.category === c);
    const a = rs.filter((r) => r.kind === 'attack');
    const b = rs.filter((r) => r.kind === 'benign');
    lines.push(
      `| ${c} | ${a.length ? `${a.filter((r) => r.got !== 'allow').length}/${a.length}` : '-'} | ${b.length ? `${b.filter((r) => r.got === 'allow' || r.got === 'sanitize').length}/${b.length}` : '-'} | ${rs.filter((r) => r.passed).length}/${rs.length} |`,
    );
  }
  lines.push('', '## Scenarios', '', '| | ID | Kind | Expected | Got | Rules fired |', '|---|---|---|---|---|---|');
  for (const r of s.results) {
    lines.push(`| ${mark(r.passed)} | \`${r.id}\` | ${r.kind} | ${r.expected} | ${r.got} | ${r.rules.join(', ') || '-'} |`);
  }
  const gaps = s.results.filter((r) => r.kind === 'known_gap');
  if (gaps.length) {
    lines.push('', '## Known gaps', '', 'Attacks the deterministic rules are not expected to catch. They are kept in the corpus so regressions and improvements are visible.', '');
    for (const g of gaps) lines.push(`- \`${g.id}\`: ${g.description}`);
  }
  if (s.failed.length) {
    lines.push('', '## Failures', '');
    for (const f of s.failed) lines.push(`- \`${f.id}\`: ${f.problems.join('; ')}`);
  }
  return `${lines.join('\n')}\n`;
}
