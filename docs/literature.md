# Literature Notes

Use this file as a working research ledger. Priority clusters:

## Benchmarks

- BIPIA
- InjecAgent
- AgentDojo
- Agent Security Bench
- Purple Llama / CyberSecEval
- Lakera PINT

## Architecture-oriented defenses

- CaMeL: capabilities and privilege separation
- ACE: abstract/concrete planning split
- Progent: deterministic privilege policies
- DRIFT: dynamic rule updates and memory isolation
- MELON: masked re-execution and tool-call comparison
- AgentArmor: runtime program-dependence analysis

## Industry controls

- OWASP Top 10 for LLM Applications
- OWASP Agentic Application Security
- OpenAI URL exfiltration controls
- Anthropic browser-use prompt injection defenses
- AWS Bedrock Agents indirect prompt injection guidance
- Microsoft prompt abuse detection playbook
- OpenTelemetry GenAI semantic conventions

## Spotlighting and ASCII smuggling

- Hines et al. (2024), "Defending Against Indirect Prompt Injection Attacks With Spotlighting"
- Greshake et al. (2023), "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"
- Rehberger, markdown image exfiltration and Unicode tag "ASCII smuggling" write-ups (embracethered.com)

## How Axiom Guard uses this

| Idea | Source | Where in Axiom Guard |
|---|---|---|
| Privilege separation between data and control | CaMeL, Progent | Taint rules `AX-ACT-002`/`AX-ACT-003`, coarse-grained because a gateway can't see the plan |
| Delimiting untrusted data | Spotlighting | `spotlight()` in `src/engine.ts` |
| Deterministic sink policy | Progent, OWASP | `AX-ACT-001` |
| Zero-click render exfiltration | Rehberger; vendor URL-exfil fixes | `AX-OUT-001`, `AX-OUT-002` |
| Detectors as signals, not boundaries | Prompt Guard, PINT results | `Detector` interface |
| Utility measured next to security | AgentDojo | Harness reports benign pass rate alongside attack containment |

## Conclusion

A better regex filter or a single prompt classifier isn't a defensible design. The useful layer is a runtime gateway that owns provenance, retrieval authorization, sink control and auditability, and uses lightweight detectors only as a fast signal.
