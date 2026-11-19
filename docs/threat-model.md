# Threat model

## Assets

| Asset | Examples |
|---|---|
| Customer data | Identifiers (SSN, account numbers), documents, conversation history |
| Tenant boundaries | Per-customer or per-partner indexes and records |
| Credentials | API keys, tokens, private keys reachable by tools or in context |
| System configuration | System prompts, tool manifests, policy |
| Integrity of actions | Tickets, status changes, emails, memory |
| Audit trail | Decisions and their evidence |

## Attacker capabilities considered

1. **Authenticated user.** Controls `input` and can attempt direct injection
   and jailbreaks.
2. **Content author.** Controls something the system later retrieves: an
   upload, a web page, an inbound email, a tool result. This is the
   indirect-injection attacker, and the main one Axiom is designed for.
3. **Compromised model behavior.** Assume either attacker can make the model
   emit anything. Axiom's output and action rules don't rely on the model
   having resisted.

## Threats → controls → tests

| Threat | Primary control | Backstop | Harness file |
|---|---|---|---|
| Direct instruction override / jailbreak | `AX-INP-001` (signal) | Output and sink rules | `01-direct-injection.yaml` |
| System prompt extraction | `AX-OUT-003` canary | `AX-INP-001` | `01-direct-injection.yaml` |
| Indirect injection driving actions | `AX-ACT-002` taint | `AX-CTX-003`, `AX-ACT-003` | `02-indirect-injection.yaml` |
| Memory poisoning | `AX-ACT-002` (memory blocks under taint) | `sinks.memory` mode | `02-indirect-injection.yaml` |
| Zero-click exfiltration via rendered images/HTML | `AX-OUT-001` | `AX-DLP-001` | `03-rendering-exfil.yaml` |
| Click-through exfiltration / disguised links | `AX-OUT-002` | `AX-DLP-001` | `03-rendering-exfil.yaml` |
| Exfiltration via tools, webhooks, email | `AX-ACT-001` default-deny | `AX-DLP-002`, `AX-ACT-003` | `04-sink-exfil.yaml` |
| SSRF-style destinations (IP literals, metadata, internal hosts) | `AX-ACT-001` URL checks | | `04-sink-exfil.yaml` |
| Cross-tenant retrieval | `AX-CTX-001` (fails closed) | | `05-retrieval.yaml` |
| Over-privileged retrieval | `AX-CTX-002` | | `05-retrieval.yaml` |
| Unicode obfuscation and ASCII smuggling | Normalization + `AX-INP-002` | | `06-obfuscation.yaml` |
| Secret or identifier leakage | `AX-DLP-001`, `AX-DLP-002` | | `07-leakage.yaml` |
| Unauthorized commitments in regulated domains | `AX-OUT-004` | Human review | `08-commitments.yaml` |
| Tampering with the audit trail | Hash chain + `axiom audit verify` | | `test/engine.test.ts` |

## Non-goals and known gaps

These are listed so nobody mistakes Axiom for something it isn't. The
`09-known-gaps.yaml` scenarios pin the current behavior.

- **Semantic detection.** Paraphrased or non-English injections get past
  `AX-INP-001` and `AX-CTX-003`. Plug in a model detector for better recall.
  The taint rules still contain injections that try to act.
- **Free-text personal data.** DLP finds structured identifiers. "Jane Doe
  earns 85000" sent to an approved host isn't detected. That needs
  field-level data classification upstream.
- **Digit-glued identifiers.** SSN and card detectors require a non-digit on
  each side, so `123-45-67890` or two card numbers run together aren't
  flagged. Dropping the boundary would redact date-like IDs such as
  `2023-12-1234`. Cloud keys have no such boundary and are caught wherever
  they appear.
- **Data in an approved destination's path.** Paths on allowlisted hosts are
  scanned for structured identifiers, not for arbitrary encodings. Keep
  `pathPrefix` tight.
- **Model correctness.** Axiom doesn't check whether an answer is grounded or
  true, only whether it makes a flagged commitment.
- **Fine-grained taint.** Taint covers the whole turn, not individual
  values. That's conservative, and it means approval prompts fire on any
  action in a tainted turn.
- **Upstream identity.** Axiom trusts `tenantId`, `principal` and chunk
  metadata from the caller. Those must come from your authenticated session
  and your index, never from the model.
- **DNS.** Hostnames aren't resolved. A public name that resolves to a
  private address has to be stopped by your egress proxy.
- **Redirects.** Axiom evaluates the proposed URL. The HTTP client that
  executes the action must not follow redirects off the allowlist.
