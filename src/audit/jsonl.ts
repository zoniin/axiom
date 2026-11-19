import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import type { AuditEvent } from './event.js';
import type { ReadableAuditSink } from './log.js';

/** Node-only append-only JSON Lines file. Writes are synchronous so a decision is never returned before it is logged. */
export class JsonlAuditSink implements ReadableAuditSink {
  constructor(readonly path: string) {}
  write(event: AuditEvent): void {
    appendFileSync(this.path, `${JSON.stringify(event)}\n`, 'utf8');
  }
  readAll(): AuditEvent[] {
    if (!existsSync(this.path)) return [];
    return readFileSync(this.path, 'utf8')
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as AuditEvent);
  }
}
