import { sha256Hex } from '../crypto/sha256.js';
import { canonicalJson } from '../policy.js';
import type { AuditEvent } from './event.js';

export const GENESIS_HASH = '0'.repeat(64);

export interface AuditSink {
  write(event: AuditEvent): void;
}

export class MemoryAuditSink implements AuditSink {
  readonly events: AuditEvent[] = [];
  write(event: AuditEvent): void {
    this.events.push(event);
  }
}

/** A sink that can read back what it wrote, so a restarted process can continue the chain. */
export interface ReadableAuditSink extends AuditSink {
  readonly path?: string;
  readAll(): AuditEvent[];
}

export function hashEvent(event: AuditEvent): string {
  const { hash: _omit, ...rest } = event;
  return sha256Hex(canonicalJson(rest));
}

/**
 * Tamper-evident audit log. Each event commits to the previous event's hash,
 * so deleting, reordering or editing any event breaks verification.
 */
export class AuditLog {
  private seq: number;
  private prevHash: string;

  constructor(
    private readonly sinks: AuditSink[],
    resumeFrom?: { seq: number; hash: string },
  ) {
    this.seq = resumeFrom ? resumeFrom.seq + 1 : 0;
    this.prevHash = resumeFrom?.hash ?? GENESIS_HASH;
  }

  static resume(sink: ReadableAuditSink, extra: AuditSink[] = []): AuditLog {
    const events = sink.readAll();
    const last = events.at(-1);
    if (events.length > 0) {
      const v = verifyChain(events);
      if (!v.ok) throw new Error(`Refusing to append to corrupted audit log ${sink.path ?? ''}: ${v.error}`);
    }
    return new AuditLog([sink, ...extra], last?.seq !== undefined && last.hash ? { seq: last.seq, hash: last.hash } : undefined);
  }

  append(event: AuditEvent): AuditEvent {
    const chained: AuditEvent = { ...event, seq: this.seq, prevHash: this.prevHash };
    chained.hash = hashEvent(chained);
    for (const sink of this.sinks) sink.write(chained);
    this.seq++;
    this.prevHash = chained.hash;
    return chained;
  }
}

export interface ChainVerification {
  ok: boolean;
  count: number;
  /** Index of the first bad event. */
  brokenAt?: number;
  error?: string;
}

export function verifyChain(events: readonly AuditEvent[]): ChainVerification {
  let prev: string | undefined;
  for (let i = 0; i < events.length; i++) {
    const e = events[i]!;
    if (!e.hash || !e.prevHash) return { ok: false, count: events.length, brokenAt: i, error: 'event is not chained' };
    if (hashEvent(e) !== e.hash) return { ok: false, count: events.length, brokenAt: i, error: 'hash mismatch (event modified)' };
    if (prev !== undefined && e.prevHash !== prev) return { ok: false, count: events.length, brokenAt: i, error: 'prevHash mismatch (event removed or reordered)' };
    if (i > 0 && e.seq !== (events[i - 1]!.seq ?? -2) + 1) return { ok: false, count: events.length, brokenAt: i, error: 'sequence gap' };
    prev = e.hash;
  }
  return { ok: true, count: events.length };
}
