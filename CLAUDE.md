# Claude Code Instructions for Axiom

You are working on Axiom, a deterministic runtime security layer for LLM applications.

## Non-negotiable engineering rules

1. Never treat an LLM classifier as the sole security boundary.
2. Retrieval authorization must happen before vector similarity results are handed to a model.
3. Untrusted content must be labeled and preserved as tainted unless explicitly declassified.
4. Outbound sinks are default-deny.
5. Markdown images, raw HTML images, data URIs, javascript URIs, and external auto-fetching content are blocked by default.
6. Every block, allow, escalate, and sanitize decision must produce an audit event.
7. Security verdicts must be deterministic in tests.
8. Do not add model calls to the hot path unless there is a feature flag and a timeout.
9. Prefer small, composable policy modules over large opaque scoring functions.
10. Any high-risk branch must fail closed.

## Layout

- `src/engine.ts`: two-pass evaluation (authorization rules, then content rules), decision reduction, sanitization, audit event
- `src/rules/`: one module per concern; register new rules in `src/rules/index.ts`
- `src/text/`: normalization, URL, markdown and DLP primitives
- `src/stream.ts`: StreamGuard; `src/core.ts` must stay free of Node built-ins (the playground bundles it)
- `harness/scenarios/*.yaml`: red-team corpus; `harness/REPORT.md` is generated
- `test/properties.test.ts`: fast-check invariants. A counterexample is a real bug: fix it and pin it with a regression test and a harness scenario
- `playground/`: browser playground; `npm run playground` builds and serves it locally

## Adding or changing a rule

1. Implement it as a `Rule` in `src/rules/` with an ID, default action, severity and description. Set `locked: true` if it guards an invariant in `SECURITY.md`.
2. Add unit tests in `test/rules.test.ts`, covering both a hit and a benign near-miss.
3. Add at least one attack and one benign scenario to the harness.
4. Run `npm run check` and commit the regenerated `harness/REPORT.md`. If schemas changed, run `npm run schemas` too.
5. Update the rules table in `README.md`.

## Gotchas

- Rules match on `ctx.normalized.*`, never raw text.
- Evidence is scrubbed by the engine, but don't put raw sensitive values in `message`.
- Write invisible Unicode in tests with `String.fromCodePoint`, never as literal characters in source.

## Style

Simple TypeScript, explicit types, Zod validation at API boundaries, and unit tests for every policy rule.
