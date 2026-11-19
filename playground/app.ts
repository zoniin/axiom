import { parse as parseYaml } from 'yaml';
import { Axiom, type Decision, type EvaluateRequest, type EvaluateResult, parsePolicy, stableBoundary } from '../src/core.js';
import { POLICY_YAML, SCENARIOS } from './data.gen.js';

type Tab = 'request' | 'policy';

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const editor = $<HTMLTextAreaElement>('editor');
const select = $<HTMLSelectElement>('scenario');
const errorBox = $('error');

const state = {
  tab: 'request' as Tab,
  request: '',
  policy: POLICY_YAML,
  axiom: undefined as Axiom | undefined,
  axiomFor: '',
  streaming: 0,
};

const DEFAULT_SCENARIO = 'indirect-upload-exfil-directive';
const DECISIONS: Decision[] = ['allow', 'sanitize', 'escalate', 'block'];

// ---------- scenarios ----------

function populateScenarios(): void {
  const byCategory = new Map<string, (typeof SCENARIOS)[number][]>();
  for (const s of SCENARIOS) byCategory.set(s.category, [...(byCategory.get(s.category) ?? []), s]);
  for (const [category, list] of byCategory) {
    const group = document.createElement('optgroup');
    group.label = category;
    for (const s of list) {
      const o = document.createElement('option');
      o.value = s.id;
      o.textContent = `${s.kind === 'benign' ? '✓ ' : s.kind === 'known_gap' ? '○ ' : '⚠ '}${s.id}`;
      group.append(o);
    }
    select.append(group);
  }
}

function loadScenario(id: string): void {
  const s = SCENARIOS.find((x) => x.id === id) ?? SCENARIOS.find((x) => x.id === DEFAULT_SCENARIO)!;
  select.value = s.id;
  const kind = s.kind === 'benign' ? 'Benign' : s.kind === 'known_gap' ? 'Known gap' : 'Attack';
  $('scenario-desc').textContent = `${kind}: ${s.description}`;
  state.request = JSON.stringify(s.request, null, 2);
  if (state.tab === 'request') editor.value = state.request;
  history.replaceState(null, '', `#${s.id}`);
  evaluate();
}

// ---------- tabs ----------

function setTab(tab: Tab): void {
  if (state.tab === 'request') state.request = editor.value;
  else state.policy = editor.value;
  state.tab = tab;
  $('tab-request').setAttribute('aria-selected', String(tab === 'request'));
  $('tab-policy').setAttribute('aria-selected', String(tab === 'policy'));
  $('format-hint').textContent = tab === 'request' ? 'JSON' : 'YAML';
  editor.value = tab === 'request' ? state.request : state.policy;
}

// ---------- evaluation ----------

function getAxiom(): Axiom {
  if (state.axiom && state.axiomFor === state.policy) return state.axiom;
  let n = 0;
  const axiom = new Axiom({ policy: parsePolicy(parseYaml(state.policy) ?? {}), idGenerator: () => `playground-${++n}` });
  state.axiom = axiom;
  state.axiomFor = state.policy;
  return axiom;
}

function evaluate(): void {
  if (state.tab === 'request') state.request = editor.value;
  else state.policy = editor.value;
  stopStream();
  let request: EvaluateRequest;
  let axiom: Axiom;
  try {
    axiom = getAxiom();
  } catch (e) {
    showError(`Policy: ${message(e)}`);
    return;
  }
  try {
    request = JSON.parse(state.request) as EvaluateRequest;
  } catch (e) {
    showError(`Request JSON: ${message(e)}`);
    return;
  }
  try {
    const t0 = performance.now();
    const result = axiom.evaluate(request);
    const ms = performance.now() - t0;
    errorBox.hidden = true;
    render(request, result, ms);
  } catch (e) {
    showError(`Request: ${message(e)}`);
  }
}

function showError(text: string): void {
  errorBox.textContent = text;
  errorBox.hidden = false;
  document.querySelector('main section:last-child')?.setAttribute('style', 'opacity:.5');
}

function message(e: unknown): string {
  if (e && typeof e === 'object' && 'issues' in e && Array.isArray((e as { issues: unknown[] }).issues)) {
    return (e as { issues: Array<{ path: unknown[]; message: string }> }).issues
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
  }
  return e instanceof Error ? e.message : String(e);
}

// ---------- rendering ----------

function render(request: EvaluateRequest, r: EvaluateResult, ms: number): void {
  document.querySelector('main section:last-child')?.removeAttribute('style');

  const badge = $('decision');
  badge.className = `badge lg b-${r.decision}`;
  badge.textContent = r.decision;
  const rank = DECISIONS.indexOf(r.decision);
  for (const [i, s] of $('lattice').querySelectorAll('span').entries()) s.classList.toggle('on', i <= rank);
  $('verdict-meta').innerHTML =
    `<strong>${r.findings.length}</strong> finding${r.findings.length === 1 ? '' : 's'} · ` +
    `<strong>${r.rulesEvaluated.length}</strong> rules · evaluated in <strong>${ms < 1 ? `${(ms * 1000).toFixed(0)} µs` : `${ms.toFixed(2)} ms`}</strong>`;

  $('rules-count').textContent = `Rules evaluated: ${r.rulesEvaluated.join(' · ')}`;
  const list = $('findings');
  list.innerHTML = r.findings.length
    ? r.findings
        .map(
          (f) => `<li>
            <span class="rule">${esc(f.ruleId)}</span>
            <span><span class="badge b-${f.action}">${f.action}</span></span>
            <span class="msg"><span class="target">${esc(f.target)}</span>${esc(f.message)}${f.evidence ? `<span class="ev">${esc(f.evidence)}</span>` : ''}</span>
          </li>`,
        )
        .join('')
    : '<li class="empty" style="display:block">No findings. Every rule ran and nothing matched.</li>';

  // Output
  const hasOutput = typeof request.output === 'string';
  $('output-panel').hidden = !hasOutput;
  if (hasOutput) {
    $('raw-output').textContent = request.output!;
    $('safe-label').textContent = r.output?.modified ? 'Safe to render (sanitized)' : 'Safe to render (unchanged)';
    $('safe-output').innerHTML = highlightMarkers(esc(r.output?.sanitized ?? ''));
  }

  // Context
  const chunks = request.context ?? [];
  $('context-panel').hidden = chunks.length === 0;
  $('chunks').innerHTML = [
    ...r.context.authorized.map(
      (c) => `<div class="chunk">
        <div class="chunk-h"><span class="id">${esc(c.id)}</span>
          <span class="badge ${c.tainted ? 'b-escalate' : 'b-neutral'}">${c.tainted ? 'tainted' : c.trust}</span>
          ${c.declassifiedBy ? `<span class="badge b-allow">declassified</span>` : ''}
          <span class="src">${esc(c.source ?? '')}</span></div>
        ${c.rendered ? `<pre>${esc(c.rendered)}</pre>` : ''}
      </div>`,
    ),
    ...r.context.dropped.map(
      (d) => `<div class="chunk dropped">
        <div class="chunk-h"><span class="id">${esc(d.id)}</span><span class="badge b-block">dropped</span><span class="src">${esc(d.ruleId)}: ${esc(d.reason)}</span></div>
      </div>`,
    ),
  ].join('');

  // Actions
  $('actions-panel').hidden = r.actions.length === 0;
  $('actions').innerHTML = r.actions
    .map(
      (
        a,
      ) => `<tr><td class="k">${a.kind}</td><td class="t">${esc(a.target)}<div class="rules-small">${a.ruleIds.join(' · ') || 'no findings'}</div></td>
        <td class="d"><span class="badge b-${a.decision}">${a.decision}</span></td></tr>`,
    )
    .join('');

  $('audit').textContent = JSON.stringify(r.audit, null, 2);
}

function highlightMarkers(html: string): string {
  return html.replace(
    /\[(REDACTED:[a-z_]+|image removed[^\]]*|active content removed|unsafe link removed)\]/g,
    '<span class="mark">[$1]</span>',
  );
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

// ---------- streaming demo ----------

function stopStream(): void {
  state.streaming++;
  $('stream').textContent = '▶ Stream it';
}

async function streamDemo(): Promise<void> {
  const run = ++state.streaming;
  let request: EvaluateRequest;
  try {
    request = JSON.parse(state.tab === 'request' ? editor.value : state.request) as EvaluateRequest;
  } catch {
    return;
  }
  const output = request.output ?? '';
  const { output: _o, actions: _a, ...base } = request;
  const guard = getAxiom().stream(base);
  const safe = $('safe-output');
  $('safe-label').textContent = 'Streaming through StreamGuard (hatched = held back, not yet shown to the user)';
  $('stream').textContent = '■ Stop';

  // Deterministic pseudo-random token sizes, like a real model stream.
  let seed = 7;
  const next = () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return 1 + (seed % 5);
  };
  let buffer = '';
  let released = '';
  for (let i = 0; i < output.length; ) {
    if (run !== state.streaming) return;
    const token = output.slice(i, i + next());
    i += token.length;
    buffer += token;
    const u = guard.push(token);
    released += u.text;
    if (u.halted) {
      safe.innerHTML = `${highlightMarkers(esc(released))}<span class="halt">\n■ stream halted: ${esc(u.reason ?? '')}</span>`;
      $('stream').textContent = '↻ Replay';
      return;
    }
    const held = buffer.slice(Math.min(stableBoundary(buffer), buffer.length));
    safe.innerHTML = `${highlightMarkers(esc(released))}<span class="held">${esc(held)}</span>`;
    await new Promise((r) => setTimeout(r, 45));
  }
  const end = guard.end();
  released += end.text;
  safe.innerHTML =
    highlightMarkers(esc(released)) + (end.halted ? `<span class="halt">\n■ stream halted: ${esc(end.reason ?? '')}</span>` : '');
  $('safe-label').textContent = end.halted ? 'Streamed (halted)' : 'Streamed (identical to the non-streamed result)';
  $('stream').textContent = '↻ Replay';
}

// ---------- theme ----------

function initTheme(): void {
  const root = document.documentElement;
  try {
    const saved = localStorage.getItem('axiom-theme');
    if (saved === 'light' || saved === 'dark') root.dataset.theme = saved;
  } catch {
    /* storage unavailable */
  }
  $('theme').addEventListener('click', () => {
    const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try {
      localStorage.setItem('axiom-theme', root.dataset.theme);
    } catch {
      /* ignore */
    }
  });
}

// ---------- wiring ----------

let timer: ReturnType<typeof setTimeout> | undefined;
editor.addEventListener('input', () => {
  clearTimeout(timer);
  timer = setTimeout(evaluate, 150);
});
editor.addEventListener('keydown', (e) => {
  if (e.key === 'Tab') {
    e.preventDefault();
    editor.setRangeText('  ', editor.selectionStart, editor.selectionEnd, 'end');
  }
});
select.addEventListener('change', () => loadScenario(select.value));
$('tab-request').addEventListener('click', () => setTab('request'));
$('tab-policy').addEventListener('click', () => setTab('policy'));
$('stream').addEventListener('click', () => {
  if ($('stream').textContent?.startsWith('■')) {
    stopStream();
    evaluate();
  } else void streamDemo();
});

initTheme();
populateScenarios();
loadScenario(decodeURIComponent(location.hash.slice(1)) || DEFAULT_SCENARIO);
