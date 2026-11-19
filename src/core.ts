// Runtime-agnostic entry: no Node built-ins. Safe for browsers and edge runtimes.

export type { AuditEvent } from './audit/event.js';
export { AuditLog, type AuditSink, GENESIS_HASH, hashEvent, MemoryAuditSink, type ReadableAuditSink, verifyChain } from './audit/log.js';
export { reduceDecisions, stricter } from './decision.js';
export type { Detector, DetectorResult } from './detectors/detector.js';
export { Axiom, type AxiomOptions, isTainted, sanitizeOutput, spotlight } from './engine.js';
export { DLP_DETECTORS, type Policy, type PolicyInput, PolicySchema, parsePolicy, policyHash } from './policy.js';
export { BUILTIN_RULES, COMMITMENT_PACKS, evaluateSink, type Rule, type RuleContext, type RuleHit } from './rules/index.js';
export { type EvaluateRequestInput, EvaluateRequestSchema } from './schema.js';
export { AgentSession } from './session.js';
export { guardStream, type StreamEnd, StreamGuard, type StreamUpdate, stableBoundary } from './stream.js';
export * from './types.js';
