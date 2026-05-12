# Controls Matrix

| Control | Status | Owner | Test target |
|---|---|---|---|
| Prompt normalization | scaffolded | runtime | Hidden HTML, markdown images, zero-width characters |
| Direct injection detection | scaffolded | runtime | Jailbreak and override patterns |
| Indirect injection detection | scaffolded | runtime | Uploaded docs, retrieved chunks, URL fragments |
| Retrieval ACL | scaffolded | app integration | Tenant and role mismatch |
| PII/NPI output detection | scaffolded | runtime | SSN, account, borrower identifiers |
| Commitment language classifier | scaffolded | runtime | APR, approval, fee waiver, denial reason |
| Sink governance | scaffolded | runtime | URL, webhook, export, email, memory writes |
| Audit events | scaffolded | platform | Every decision has traceable event |
| Red-team harness | scaffolded | security | Attack success and utility metrics |
| Proof lane replay | deferred | research | High-consequence actions only |
