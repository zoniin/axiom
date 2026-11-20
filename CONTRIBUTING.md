# Contributing

Thanks for helping. Axiom Guard is security tooling, so changes are held to a few
extra rules. They're short.

## Setup

```bash
npm ci
npm run check   # lint, typecheck, tests with coverage, harness
```

`npm run playground` builds and serves the browser playground locally.
`npm run e2e` runs the browser end-to-end test against the built playground
(run `npm run playground:build` first). `npm run pack:test` installs the
packed tarball into an empty project and exercises it like a consumer.

## Changing or adding a rule

1. Implement it as a `Rule` in `src/rules/` (ID, default action, severity,
   description). Set `locked: true` if it protects an invariant in
   [SECURITY.md](SECURITY.md).
2. Match on `ctx.normalized.*`, never raw text.
3. Add unit tests for a hit and for a benign near-miss.
4. Add at least one attack scenario and one benign scenario under
   `harness/scenarios/`, then regenerate `harness/REPORT.md` with
   `npm run harness`. CI fails if it is stale.
5. Update the rules table in the README and add a CHANGELOG entry.

## Fuzzing failures

If `test/properties.test.ts` reports a counterexample, it's a real bug.
fast-check prints the seed and the shrunk input. Fix the cause, then pin it
with a regression unit test and a harness scenario. Don't loosen the property
to make it pass.

## Ground rules

- Deterministic: same request and policy, same result. No clocks, randomness
  or network in rules.
- Fail closed: errors and unknown cases block.
- No model calls on the hot path. Model detectors go behind the `Detector`
  interface with a flag and a timeout.
- `src/core.ts` must stay free of Node built-ins; the playground bundles it.
- Never put raw request text or secrets into findings or audit events.

## Reporting vulnerabilities

Use [private vulnerability reporting](https://github.com/zoniin/axiom/security/advisories/new),
not public issues.
