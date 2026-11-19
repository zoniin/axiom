# Roadmap

## Done (v0.4)

- Deterministic engine with a decision lattice, locked rules and fail-closed errors
- Retrieval authorization (tenant, role, clearance) before anything else runs
- Taint tracking, spotlighting and declassification
- Default-deny sinks for http, email, tools, memory, export
- Rendering controls for images, active HTML, dangerous URIs and link defanging
- Structurally validated DLP over output and action arguments, including encoded URL parts
- Canary-based prompt leak detection
- Hash-chained audit log with verification and resume
- Detector adapter with feature flag and timeout
- HTTP gateway, CLI, red-team harness with a generated report
- Streaming output guard with prefix-stability checking
- Property-based fuzzing of the security invariants
- Runtime-agnostic core and a browser playground on GitHub Pages
- Agent sessions with persistent taint, and Claude tool-runner integration (`guardTool`)
- Custom harness runs (`--policy`, `--scenarios`), coverage gates, Docker smoke test

## Next

- **OpenTelemetry spans** per evaluation, using GenAI semantic conventions
- **Reference detector adapters** (Prompt Guard, a hosted classifier) shipped as optional packages
- **Per-tenant policy bundles**, signed, with hot reload
- **Multilingual injection patterns**, starting with the known-gap scenarios
- **Tool manifest pinning**: hash tool descriptions so a changed MCP manifest escalates
- **Imported benchmark fixtures**: adapters for AgentDojo and InjecAgent cases in the harness format

## Later

- Per-value taint for agents that expose their plan (CaMeL-style)
- Masked re-execution for high-consequence actions (MELON-style)
