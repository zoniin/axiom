# Changelog

## 0.4.0

### Added
- `AgentSession` (`axiom.session()`): taint persists across turns of a multi-turn agent, with per-chunk declassification and an audited action history.
- Claude integration (`axiom-guard/anthropic`): `guardTool()` wraps SDK tool-runner tools so each call is checked before `run` and each result is recorded as spotlighted, untrusted context; `checkToolUses()` for manual loops. Type-only dependency on `@anthropic-ai/sdk`.
- `examples/claude-agent.ts`: a tool-runner agent with guarded tools.
- `axiom harness --policy <file> --scenarios <dir>` to test your own policy against your own corpus.
- Biome linting and formatting, coverage thresholds, a Docker build and smoke test in CI.

### Fixed
- Audit verification now detects removal of the oldest events (the chain must start at genesis or at a supplied anchor).

### Changed
- The harness uses `policies/fintech-support.yaml` directly (removed the duplicate `harness/policy.yaml`).

## 0.3.0

### Added
- `StreamGuard` / `guardStream` for token streams, with a prefix-stability check.
- Property-based tests (fast-check) for the security invariants.
- Browser playground on GitHub Pages; runtime-agnostic `axiom-guard/core` entry.
- `npm run bench`.

### Fixed
- Images with nested-bracket alt text and shortcut references were not detected.
- Sanitizer markers could combine with leftover markup into a new live image.
- Secrets glued to letters evaded DLP and could reach audit evidence.

## 0.2.0

Rebuilt from the scaffold: two-pass engine, 14 rules, taint tracking, default-deny sinks, hash-chained audit, HTTP gateway, CLI, red-team harness.
