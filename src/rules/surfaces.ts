import { urlDataSurfaces } from '../text/urls.js';
import type { ProposedAction } from '../types.js';

/** Every string in an action that could carry data out: target, decoded URL parts, payload leaves. */
export function actionSurfaces(action: ProposedAction): string[] {
  const out: string[] = [action.target];
  if (action.kind === 'http') {
    try {
      out.push(...urlDataSurfaces(new URL(action.target)));
    } catch {
      /* unparseable URLs are rejected by AX-ACT-001 */
    }
  }
  collectStrings(action.payload, out, 0);
  return out;
}

function collectStrings(value: unknown, out: string[], depth: number): void {
  if (depth > 20 || value === null || value === undefined) return;
  if (typeof value === 'string') {
    out.push(value);
  } else if (typeof value === 'number' || typeof value === 'bigint') {
    out.push(String(value));
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out, depth + 1);
  } else if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      collectStrings(v, out, depth + 1);
    }
  }
}
