# Security policy

Axiom is security tooling, so a bypass is a vulnerability.

## Reporting

Please report bypasses, exfiltration paths or tenant-isolation flaws through
[GitHub private vulnerability reporting](https://github.com/zoniin/axiom/security/advisories/new),
not public issues. Include a request that reproduces it. A harness scenario in
YAML is ideal.

Paraphrased or non-English injections that get past `AX-INP-001` without
causing a harmful action are known limitations (see `docs/threat-model.md`).
New examples are welcome as normal pull requests that add `known_gap` scenarios.

## Invariants

A change that breaks any of these is a security bug:

- A chunk from another tenant never reaches `context.authorized`, and the request blocks.
- No side effect is allowed unless the policy explicitly allows it.
- Untrusted, non-declassified context never allows a memory write or an untrusted-supplied destination.
- Output marked `allow` or `sanitize` contains no auto-fetching content.
- Locked rules can't be weakened by policy.
- A rule error never produces `allow`.
- Audit events contain no raw request text or unmasked sensitive values.
