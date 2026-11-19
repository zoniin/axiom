# Changelog

## 0.5.0

### Added
- Agent replay in the playground (`#agent`): a scripted Claude tool-use turn run through the real `AgentSession` and `guardTool`, with interactive approval. Recorded as `docs/agent-replay.gif`.
- Open Graph and Twitter card metadata plus a social preview image for link unfurls.
- Release workflow: tag `v*` runs the full checks, creates a GitHub release from this changelog, and publishes to npm with provenance when `NPM_TOKEN` is set.
- Installed-package smoke test (`npm run pack:test`) in CI: installs the packed tarball into an empty project and exercises every entry point and the CLI.
- Installable from GitHub today: `npm install github:zoniin/axiom` (builds via `prepare`).

### Changed
- Renamed to **Axiom Guard**. The CLI is now `axiom-guard` (was `axiom`, which collides with Axiom.co's CLI). Library API, rule IDs and audit format are unchanged.
- Source maps embed their sources.

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
