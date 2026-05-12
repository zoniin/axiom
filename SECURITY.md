# Security Policy

This repository contains security-sensitive code for LLM runtime protection.

## Reporting vulnerabilities

Do not open public GitHub issues for exploitable bypasses, exfiltration paths, or tenant isolation flaws. Report privately to the Axiom team.

## Security invariants

- No cross-tenant data access.
- No unapproved external sink invocation.
- No sensitive data in model-rendered URLs.
- No raw untrusted document text passed to action-capable agents without labels.
- No memory writes from tainted content without declassification.
