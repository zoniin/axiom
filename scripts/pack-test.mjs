// Installs the packed tarball into an empty project and uses it the way a
// consumer would: all three entry points, the CLI, and the Claude adapter
// without @anthropic-ai/sdk installed (it must be a type-only dependency).
//   node scripts/pack-test.mjs
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
const root = resolve('.');
const out = mkdtempSync(join(tmpdir(), 'axiom-pack-'));
const tarball = run('npm', ['pack', '--silent', '--pack-destination', out], root).trim().split('\n').at(-1);
const app = join(out, 'app');
run('mkdir', ['-p', app]);
writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'consumer', private: true, type: 'module' }));
run('npm', ['install', '--silent', '--no-audit', '--no-fund', join(out, tarball)], app);

writeFileSync(
  join(app, 'check.mjs'),
  `
import assert from 'node:assert/strict';
import { Axiom, loadPolicyFile } from 'axiom-guard';
import * as core from 'axiom-guard/core';
import { guardTool } from 'axiom-guard/anthropic';

const ax = new Axiom();
assert.equal(ax.evaluate({ tenantId: 't', output: '![](https://e.io/x)' }).decision, 'block');
assert.equal(typeof core.Axiom, 'function');
loadPolicyFile('node_modules/axiom-guard/policies/default.yaml');

const session = ax.session({ tenantId: 't', principal: { roles: [], clearance: 'internal' } });
const tool = guardTool(session, { name: 'shell', run: async () => 'ran' });
assert.match(await tool.run({}), /^Declined by policy \\(block\\)/);
console.log('imports ok');
`,
);
console.log(run('node', ['check.mjs'], app).trim());
console.log(run('npx', ['--no-install', 'axiom-guard', 'rules'], app).split('\n')[0]);
const harness = JSON.parse(run('npx', ['--no-install', 'axiom-guard', 'harness', '--json'], app));
if (harness.failed.length) throw new Error(`harness failed in installed package: ${harness.failed.map((f) => f.id)}`);
console.log(`harness ok: ${harness.total} scenarios from the installed package`);
