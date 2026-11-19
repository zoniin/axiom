/**
 * Claude API integration.
 *
 * Uses type-only imports from `@anthropic-ai/sdk`, so Axiom has no runtime
 * dependency on the SDK. Two entry points:
 *
 * - `guardTool(session, tool)` wraps a runnable tool (from `betaZodTool`,
 *   `betaTool` or `mcpTool`) for the SDK's tool runner. Before `run` executes,
 *   the call is checked against policy and session taint. Afterwards, the
 *   result is recorded as untrusted context and handed back to the model
 *   spotlighted.
 * - `checkToolUses(session, message)` does the same check for a manual
 *   agentic loop, given a response's `tool_use` blocks.
 */
import type Anthropic from '@anthropic-ai/sdk';
import type { AgentSession } from '../session.js';
import type { ActionVerdict, ProposedAction, TrustLevel } from '../types.js';

type Promisable<T> = T | Promise<T>;
/** What a runnable tool may return: the content of a beta `tool_result` block. */
type ToolResultContent = NonNullable<Anthropic.Beta.BetaToolResultBlockParam['content']>;

/** The shape the SDK's tool runners call: `BetaRunnableTool<Input>`. */
export interface RunnableToolLike {
  name: string;
  // biome-ignore lint/suspicious/noExplicitAny: matches any tool's input type; narrowed by ToolInput<T>.
  run: (args: any, ...rest: any[]) => Promisable<ToolResultContent>;
}

/** The input type a runnable tool's `run` accepts. */
export type ToolInput<T extends RunnableToolLike> = Parameters<T['run']>[0];

export interface GuardToolOptions<Input> {
  /**
   * Maps a call to the side effect it performs. Defaults to a `tool` action
   * named after the tool, with the input as payload. Map tools that reach the
   * network or send messages to `http` / `email` so destination rules apply.
   */
  toAction?: (input: Input) => ProposedAction;
  /**
   * Called when policy says `escalate`. Return true to run the tool anyway
   * (e.g. after a human approves). Without it, escalations are declined.
   */
  approve?: (verdict: ActionVerdict, input: Input) => Promisable<boolean>;
  /** Trust level of this tool's output. Defaults to `untrusted`. */
  resultTrust?: TrustLevel;
}

/**
 * Wraps a runnable tool so every call goes through Axiom. The returned object
 * is the same tool with a guarded `run`, so it drops straight into
 * `client.beta.messages.toolRunner({ tools: [...] })`.
 */
export function guardTool<T extends RunnableToolLike>(session: AgentSession, tool: T, options: GuardToolOptions<ToolInput<T>> = {}): T {
  const original = tool.run.bind(tool);
  const run = async (input: ToolInput<T>, ...rest: unknown[]): Promise<ToolResultContent> => {
    const action = options.toAction?.(input) ?? { kind: 'tool', target: tool.name, payload: input };
    const { verdict, result } = session.checkAction(action);

    let allowed = verdict.decision === 'allow';
    if (verdict.decision === 'escalate' && options.approve) allowed = await options.approve(verdict, input);
    if (!allowed) {
      const reasons = result.findings
        .filter((f) => f.target === 'action:0')
        .map((f) => `${f.ruleId}: ${f.message}`)
        .join(' ');
      // Returned, not thrown: the model learns the call was declined and can adapt (documented runner pattern).
      return `Declined by policy (${verdict.decision}). ${reasons}`.trim();
    }

    const output = await original(input, ...rest);
    return recordResult(session, tool.name, output, options.resultTrust);
  };
  return Object.assign(Object.create(Object.getPrototypeOf(tool) as object) as T, tool, { run });
}

/** Records tool output in the session and returns it spotlighted for the model. */
function recordResult(session: AgentSession, name: string, output: ToolResultContent, trust: TrustLevel = 'untrusted'): ToolResultContent {
  if (typeof output === 'string') return session.recordToolResult(name, output, { trust }).rendered ?? output;
  return output.map((block) =>
    block.type === 'text' ? { ...block, text: session.recordToolResult(name, block.text, { trust }).rendered ?? block.text } : block,
  );
}

export interface ToolUseCheck {
  block: Anthropic.ToolUseBlock;
  verdict: ActionVerdict;
  /** A ready-made `tool_result` to send back when the call is not allowed. */
  declined?: Anthropic.ToolResultBlockParam;
}

/**
 * Manual-loop variant: checks every `tool_use` block in a response.
 * Execute the allowed ones, send `declined` for the rest, and pass each
 * executed result through `session.recordToolResult`.
 */
export function checkToolUses(
  session: AgentSession,
  message: Pick<Anthropic.Message, 'content'>,
  toAction: (block: Anthropic.ToolUseBlock) => ProposedAction = (b) => ({ kind: 'tool', target: b.name, payload: b.input }),
): ToolUseCheck[] {
  return message.content
    .filter((b): b is Anthropic.ToolUseBlock => b.type === 'tool_use')
    .map((block) => {
      const { verdict } = session.checkAction(toAction(block));
      if (verdict.decision === 'allow') return { block, verdict };
      return {
        block,
        verdict,
        declined: {
          type: 'tool_result',
          tool_use_id: block.id,
          is_error: true,
          content: `Declined by policy (${verdict.decision}): ${verdict.ruleIds.join(', ')}`,
        },
      };
    });
}

/** Concatenated text of a response, for `session.checkOutput`. */
export function responseText(message: Pick<Anthropic.Message, 'content'> | Pick<Anthropic.Beta.BetaMessage, 'content'>): string {
  return (message.content as Array<{ type: string; text?: string }>)
    .filter((b) => b.type === 'text')
    .map((b) => b.text ?? '')
    .join('');
}
