// Runtime-agnostic entry: no Node built-ins. Safe for browsers and edge runtimes.
export { StreamGuard, guardStream, stableBoundary, type StreamUpdate, type StreamEnd } from './stream.js';
export { Axiom, sanitizeOutput, spotlight, isTainted, type AxiomOptions } from './engine.js';
export { parsePolicy, policyHash, PolicySchema, DLP_DETECTORS, type Policy, type PolicyInput } from './policy.js';
export { EvaluateRequestSchema, type EvaluateRequestInput } from './schema.js';
export { AuditLog, MemoryAuditSink, verifyChain, hashEvent, GENESIS_HASH, type AuditSink, type ReadableAuditSink } from './audit/log.js';
export type { AuditEvent } from './audit/event.js';
export type { Detector, DetectorResult } from './detectors/detector.js';
export { BUILTIN_RULES, COMMITMENT_PACKS, evaluateSink, type Rule, type RuleContext, type RuleHit } from './rules/index.js';
export { reduceDecisions, stricter } from './decision.js';
export * from './types.js';
