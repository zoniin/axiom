// Browser end-to-end test of the built playground (run after `npm run playground:build`).
//   node scripts/e2e.mjs
// Starts the static server, drives both modes in Chromium, and fails on wrong
// verdicts, console errors or horizontal overflow on a phone-sized viewport.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chromium } from 'playwright';

const PORT = 5199;
const BASE = `http://localhost:${PORT}/`;
const server = spawn('npx', ['tsx', 'playground/serve.ts'], { env: { ...process.env, PORT: String(PORT) }, stdio: 'ignore' });

async function waitForServer() {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(BASE)).ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('playground server did not start');
}

const errors = [];
const browser = await chromium.launch();
try {
  await waitForServer();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));

  // Playground: a scenario loads with the expected verdict, and live edits re-evaluate.
  await page.goto(`${BASE}#indirect-upload-exfil-directive`);
  await page.waitForSelector('#decision.b-block');
  await page.selectOption('#scenario', 'benign-rich-markdown');
  await page.waitForSelector('#decision.b-allow');
  await page.fill('#editor', JSON.stringify({ tenantId: 'acme', output: 'hi ![x](https://e.io/a)' }));
  await page.waitForSelector('#decision.b-block');

  // Streaming demo halts before the image renders.
  await page.selectOption('#scenario', 'render-markdown-image-beacon');
  await page.click('#stream');
  await page.waitForSelector('.halt', { timeout: 15000 });
  assert.match(await page.textContent('#safe-output'), /stream halted: AX-OUT-001/);
  assert.doesNotMatch(await page.textContent('#safe-output'), /attacker\.example/);

  // Agent replay, auto-approve path.
  await page.goto(`${BASE}?auto#agent`);
  await page.waitForSelector('#tally:not([hidden])', { timeout: 30000 });
  const badges = await page.$$eval('.step .badge', (b) => b.map((x) => x.textContent));
  assert.deepEqual(badges, ['allow · executed', 'block · not executed', 'escalate · approved, executed', 'sanitize · rendered sanitized']);
  assert.match(await page.textContent('#tally'), /hash chain verified/);
  assert.ok(await page.isHidden('main'), 'playground grid must be hidden in agent mode');

  // Agent replay, deny path.
  await page.uncheck('#agent-auto');
  await page.click('#agent-play');
  await page.click('.approval [data-a="deny"]', { timeout: 15000 });
  await page.waitForSelector('#tally:not([hidden])', { timeout: 30000 });
  assert.equal((await page.$$eval('.step .badge', (b) => b.map((x) => x.textContent)))[2], 'escalate · denied, not executed');

  // Phone layout.
  const phone = await browser.newPage({ viewport: { width: 390, height: 844 } });
  phone.on('pageerror', (e) => errors.push(String(e)));
  for (const hash of ['#sink-base64-ssn-to-approved-host', '#agent']) {
    await phone.goto(BASE + hash);
    await phone.waitForTimeout(300);
    assert.equal(
      await phone.evaluate(() => document.documentElement.scrollWidth > window.innerWidth),
      false,
      `horizontal overflow at ${hash}`,
    );
  }

  assert.deepEqual(errors, [], 'browser console errors');
  console.log('playground e2e: all checks passed');
} finally {
  await browser.close();
  server.kill();
}
