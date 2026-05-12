# Claude Code Instructions for Axiom

You are working on Axiom, a runtime security layer for AI applications.

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

## Implementation sequence

Start with `services/runtime-gateway/src/policy.ts` and make the rules pass harness tests. Then add persistence, observability, and optional model adapters.

## Style

Use simple TypeScript, explicit types, Zod validation at API boundaries, and unit tests for every policy rule.
