package axiom.access

default allow = false

allow {
  input.request.tenant_id == input.chunk.tenant_id
  input.request.role in input.chunk.allowed_roles
  input.request.sensitivity_clearance >= input.chunk.sensitivity_level
}
