# Roadmap

## Milestone 1: Deterministic runtime gateway

- Build `/health` and `/v1/evaluate`
- Validate request schemas
- Implement deterministic policy checks
- Emit audit event object
- Add tests

Exit criteria: local requests return allow, block, or escalate with rule IDs.

## Milestone 2: Sink controls

- URL canonicalization
- Markdown image and raw HTML image block
- Allowed destination list
- Redirect policy placeholder
- Sensitive data in URL detector

Exit criteria: all exfiltration sink tests block.

## Milestone 3: Retrieval and provenance

- Chunk metadata schema
- Tenant and role checks
- Taint labels
- Citation requirement placeholder

Exit criteria: cross-tenant chunk cannot enter model context.

## Milestone 4: Detection plug-ins

- Prompt Guard or equivalent adapter interface
- Pytector/Rebuff baseline comparison adapter if useful
- Feature flags and timeout budgets

Exit criteria: model detectors can be enabled without changing core policy logic.

## Milestone 5: Pilot evidence pack

- Attack suite report
- Utility suite report
- Control matrix
- Audit sample bundle
- Open issues and exception register
