/**
 * Instruction-injection heuristics. These are a fast, explainable signal, not
 * a security boundary: an attacker who knows the list can phrase around it.
 * The boundary is enforced by retrieval authorization, taint tracking and
 * default-deny sinks. All patterns run against normalized text.
 */

export interface InjectionPattern {
  id: string;
  re: RegExp;
}

const W = String.raw`[^.!?\n]`; // "within the same sentence"

/** Attempts to override the system's instructions. Applied to user input and to context. */
export const DIRECT_PATTERNS: InjectionPattern[] = [
  {
    id: 'ignore_previous',
    re: new RegExp(
      String.raw`\b(ignore|disregard|forget|override|bypass|discard)\b${W}{0,30}\b(previous|prior|above|earlier|preceding|all|your|system|developer|original|initial|existing)\b${W}{0,30}\b(instructions?|rules|directions|guidelines|prompts?|constraints|guardrails|programming)\b`,
      'i',
    ),
  },
  { id: 'ignore_everything', re: /\b(ignore|disregard|forget)\b (everything|all|anything) (above|before|prior|previously|you were told)/i },
  {
    id: 'reveal_prompt',
    re: new RegExp(
      String.raw`\b(reveal|print|show|repeat|output|display|leak|dump|tell me|give me|what (is|are|was|were))\b${W}{0,30}\b(your|the) (full |exact |entire )?(system|hidden|initial|original|developer|secret|confidential) (prompt|instructions|message|rules|configuration)`,
      'i',
    ),
  },
  { id: 'repeat_above', re: /\b(repeat|print|output) (the )?(words|text|everything) above\b/i },
  {
    id: 'role_reassignment',
    re: new RegExp(
      String.raw`\byou are (now|no longer)\b${W}{0,40}\b(dan|jailbroken|unrestricted|unfiltered|uncensored|developer mode|evil|without (any )?(restrictions|rules|limits|filters))`,
      'i',
    ),
  },
  { id: 'mode_switch', re: /\b(enter|enable|activate|switch to|turn on)\b (developer|god|admin|debug|dan|jailbreak|sudo|maintenance) mode\b/i },
  { id: 'dan', re: /\bdo anything now\b|\bDAN\b(?= (mode|prompt|jailbreak))/i },
  { id: 'fake_chat_delimiter', re: /<\|\s*(im_start|im_end|system|endoftext|start_header_id)\s*\|>|\[\/?(system|inst)\]|<\/?(system|sys)>/i },
  { id: 'fake_system_header', re: /(^|\s)(#{2,3}|-{3,}|={3,}) ?(system|admin|developer)( message| prompt| override)?\s*:/i },
  { id: 'new_instructions', re: /\b(new|updated|revised|real|actual|true) (system )?instructions\s*:/i },
  {
    id: 'no_restrictions',
    re: /\b(without|ignoring|free of|no longer bound by) (any |your |all )?(ethical|safety|content|moral)? ?(guidelines|filters|restrictions|policies|safeguards)\b|\bpretend (that )?you (have no|are not bound by|don'?t have) (rules|restrictions|guidelines|filters)/i,
  },
];

/** Signals that third-party content is trying to address the model. Applied to untrusted context only. */
export const INDIRECT_PATTERNS: InjectionPattern[] = [
  { id: 'addresses_ai', re: /\b(attention|note|important|message|instructions?) (to|for) (the |any )?(ai|assistant|llm|language model|model|agent|chatbot|copilot)\b/i },
  { id: 'if_you_are_ai', re: /\bif you are an? (ai|llm|large language model|language model|assistant|agent|bot)\b/i },
  { id: 'ai_reading_this', re: /\b(ai|assistant|agent|model|llm)s? (that is |who is )?(reading|processing|summari[sz]ing|parsing|analy[sz]ing) this\b/i },
  { id: 'conceal_from_user', re: /\b(do not|don'?t|never) (tell|inform|mention (this )?to|reveal (this )?to|alert|notify|let) the user\b|\bwithout (telling|alerting|notifying|informing) the user\b/i },
  {
    id: 'exfil_directive',
    re: new RegExp(
      String.raw`\b(send|forward|email|post|upload|transmit|exfiltrate|submit|copy)\b${W}{0,80}\b(to|at|into)\b${W}{0,20}(https?:\/\/|[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]{2,}|webhook)`,
      'i',
    ),
  },
  {
    id: 'render_directive',
    re: new RegExp(String.raw`\b(include|render|add|insert|append|embed|output)\b${W}{0,40}\b(image|markdown|pixel|img tag)\b${W}{0,80}https?:\/\/`, 'i'),
  },
  { id: 'assistant_impersonation', re: /(^|\s)(assistant|system)\s*:\s*(sure|ok|okay|understood|i will)\b/i },
];

export function matchPatterns(text: string, patterns: readonly InjectionPattern[]): Array<{ id: string; match: string }> {
  const hits: Array<{ id: string; match: string }> = [];
  for (const p of patterns) {
    const m = p.re.exec(text);
    if (m) hits.push({ id: p.id, match: m[0] });
  }
  return hits;
}
