import type { EvaluateRequest, Finding } from '../types.js';

/**
 * Adapter for optional model-based detectors (Prompt Guard, a hosted
 * classifier, an LLM judge...). Detectors are advisory by construction:
 * - they run only when named in `policy.detectors.enabled`
 * - they are bounded by `policy.detectors.timeoutMs`
 * - they can add an `escalate` finding, never remove or downgrade one
 * - a timeout or error is recorded but does not change the decision,
 *   because the deterministic rules are the boundary, not the detector
 */
export interface Detector {
  id: string;
  /** Which request texts to scan. */
  surfaces: Array<'input' | 'context' | 'output'>;
  detect(text: string, options: { signal: AbortSignal }): Promise<DetectorResult>;
}

export interface DetectorResult {
  flagged: boolean;
  score?: number;
  label?: string;
}

const DETECTOR_RULE = 'AX-SYS-002';

export async function runDetectors(detectors: Detector[], request: EvaluateRequest, timeoutMs: number): Promise<Finding[]> {
  const jobs: Array<Promise<Finding | undefined>> = [];
  for (const d of detectors) {
    for (const [target, text] of surfacesFor(d, request)) jobs.push(runOne(d, target, text, timeoutMs));
  }
  const results = await Promise.all(jobs);
  return results.filter((f): f is Finding => f !== undefined);
}

function surfacesFor(d: Detector, r: EvaluateRequest): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (d.surfaces.includes('input') && r.input) out.push(['input', r.input]);
  if (d.surfaces.includes('output') && r.output) out.push(['output', r.output]);
  if (d.surfaces.includes('context')) {
    for (const c of r.context ?? []) if (c.content && c.trust === 'untrusted') out.push([`context:${c.id}`, c.content]);
  }
  return out;
}

async function runOne(d: Detector, target: string, text: string, timeoutMs: number): Promise<Finding | undefined> {
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<'timeout'>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve('timeout');
    }, timeoutMs);
  });
  try {
    const r = await Promise.race([d.detect(text, { signal: controller.signal }), timeout]);
    if (r === 'timeout') {
      return {
        ruleId: DETECTOR_RULE,
        stage: 'system',
        action: 'allow',
        severity: 'low',
        target,
        message: `Detector ${d.id} timed out after ${timeoutMs}ms; deterministic rules still apply.`,
      };
    }
    if (!r.flagged) return undefined;
    const score = r.score !== undefined ? ` (score ${r.score.toFixed(2)})` : '';
    return {
      ruleId: DETECTOR_RULE,
      stage: 'system',
      action: 'escalate',
      severity: 'medium',
      target,
      message: `Detector ${d.id} flagged ${r.label ?? 'content'}${score}.`,
    };
  } catch (err) {
    return {
      ruleId: DETECTOR_RULE,
      stage: 'system',
      action: 'allow',
      severity: 'low',
      target,
      message: `Detector ${d.id} failed: ${err instanceof Error ? err.message : String(err)}.`,
    };
  } finally {
    clearTimeout(timer);
  }
}
