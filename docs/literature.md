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

## Product conclusion

Axiom should not compete as a better regex filter or single prompt classifier. The credible wedge is a runtime gateway that owns provenance, retrieval authorization, sink control, and auditability, while using lightweight detectors as a fast signal layer.
