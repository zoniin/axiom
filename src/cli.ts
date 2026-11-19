#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { JsonlAuditSink } from './audit/jsonl.js';
import { AuditLog, verifyChain } from './audit/log.js';
import { Axiom } from './engine.js';
import type { Policy } from './policy.js';
import { loadPolicyFile } from './policy-file.js';
import type { EvaluateResult } from './types.js';

const HELP = `axiom: deterministic runtime security for LLM apps

Usage:
  axiom check <request.json> [--policy file]   Evaluate one request, print findings
  axiom serve [--policy file] [--port 8787] [--audit audit.jsonl]
  axiom harness [--report REPORT.md] [--json] [--policy file] [--scenarios dir]
                                               Run a scenario corpus (default: the built-in red-team corpus)
  axiom audit verify <audit.jsonl>             Verify a hash-chained audit log
  axiom rules                                  List built-in rules
`;

const COLORS = { allow: '\x1b[32m', sanitize: '\x1b[36m', escalate: '\x1b[33m', block: '\x1b[31m' } as const;
const RESET = '\x1b[0m';
const color = (d: keyof typeof COLORS, text: string = d) => (process.stdout.isTTY ? `${COLORS[d]}${text}${RESET}` : text);

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      policy: { type: 'string', short: 'p' },
      port: { type: 'string' },
      audit: { type: 'string' },
      report: { type: 'string' },
      scenarios: { type: 'string' },
      json: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const [cmd, ...rest] = positionals;
  const policy: Policy | undefined = values.policy ? loadPolicyFile(values.policy) : undefined;

  if (values.help || !cmd) {
    process.stdout.write(HELP);
    return cmd ? 0 : 1;
  }

  switch (cmd) {
    case 'check': {
      const file = rest[0];
      if (!file) throw new Error('check requires a request JSON file');
      const result = new Axiom({ policy }).evaluate(JSON.parse(readFileSync(file, 'utf8')));
      if (values.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      else printResult(result);
      return result.decision === 'block' ? 2 : 0;
    }
    case 'serve': {
      const [{ serve }, { createApp }] = await Promise.all([import('@hono/node-server'), import('./server.js')]);
      const audit = values.audit ? AuditLog.resume(new JsonlAuditSink(values.audit)) : undefined;
      const axiom = new Axiom({ policy, audit });
      const port = Number(values.port ?? process.env.PORT ?? 8787);
      serve({ fetch: createApp(axiom).fetch, port });
      console.log(`axiom gateway listening on :${port} (policy "${axiom.policy.name}" ${axiom.policyHash.slice(0, 12)})`);
      return new Promise(() => {});
    }
    case 'harness': {
      const { runHarness, renderReport, loadScenarios } = await import('./harness.js');
      const summary = runHarness({
        ...(values.policy ? { policyFile: values.policy } : {}),
        ...(values.scenarios ? { scenarios: loadScenarios(values.scenarios) } : {}),
      });
      if (values.report) {
        const { writeFileSync } = await import('node:fs');
        writeFileSync(values.report, renderReport(summary));
      }
      if (values.json) process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
      else process.stdout.write(renderReport(summary, { color: process.stdout.isTTY }));
      return summary.failed.length > 0 ? 1 : 0;
    }
    case 'audit': {
      if (rest[0] !== 'verify' || !rest[1]) throw new Error('usage: axiom audit verify <file>');
      const events = new JsonlAuditSink(rest[1]).readAll();
      const v = verifyChain(events);
      console.log(v.ok ? `OK: ${v.count} events, chain intact` : `BROKEN at event ${v.brokenAt}: ${v.error}`);
      return v.ok ? 0 : 1;
    }
    case 'rules': {
      const { BUILTIN_RULES } = await import('./rules/index.js');
      for (const r of BUILTIN_RULES) {
        console.log(`${r.id}  ${color(r.defaultAction, r.defaultAction.padEnd(8))}  ${r.locked ? 'locked' : '      '}  ${r.title}`);
      }
      return 0;
    }
    default:
      process.stderr.write(`unknown command: ${cmd}\n\n${HELP}`);
      return 1;
  }
}

function printResult(r: EvaluateResult): void {
  console.log(`decision: ${color(r.decision, r.decision.toUpperCase())}  (${r.rulesEvaluated.length} rules evaluated)`);
  for (const f of r.findings) {
    console.log(
      `  ${f.ruleId}  ${color(f.action, f.action.padEnd(8))}  ${f.target.padEnd(16)}  ${f.message}${f.evidence ? `  [${f.evidence}]` : ''}`,
    );
  }
  if (r.context.dropped.length) console.log(`dropped context: ${r.context.dropped.map((d) => d.id).join(', ')}`);
  if (r.output?.modified) console.log(`\nsanitized output:\n  ${r.output.sanitized}`);
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    console.error(`axiom: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  },
);
