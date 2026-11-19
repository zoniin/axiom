import { defangLinks, findActiveContent } from '../text/markdown.js';
import { stripHidden } from '../text/normalize.js';
import { excerpt, type Rule } from './rule.js';

export const activeContent: Rule = {
  id: 'AX-OUT-001',
  title: 'Auto-fetching or executable content in output',
  stage: 'output',
  severity: 'critical',
  defaultAction: 'block',
  description:
    'Markdown images, reference images, active HTML (img, iframe, script, svg, meta refresh, forms), event handlers, CSS url() and javascript:/data:/vbscript:/file: URIs. Renderers fetch these with no user interaction, which makes them the primary zero-click exfiltration channel.',
  evaluate(ctx) {
    if (!ctx.request.output) return [];
    // Check both forms: stripping invisible characters can create or destroy token boundaries.
    const raw = ctx.request.output;
    const stripped = stripHidden(raw);
    const found = [...findActiveContent(stripped), ...(stripped === raw ? [] : findActiveContent(raw))];
    if (found.length === 0) return [];
    const kinds = [...new Set(found.map((f) => f.kind))];
    return [
      {
        target: 'output',
        action: ctx.policy.rendering.activeContent,
        message: `Output contains ${found.length} auto-fetching/active element(s): ${kinds.join(', ')}.`,
        evidence: excerpt(found[0]!.match),
      },
    ];
  },
};

export const untrustedLinks: Rule = {
  id: 'AX-OUT-002',
  title: 'Links to unapproved hosts',
  stage: 'output',
  severity: 'medium',
  defaultAction: 'sanitize',
  description:
    'Markdown links to hosts outside `rendering.linkAllowHosts` are rewritten to show their real destination; bare URLs to unapproved hosts lose their query string and fragment, which is where exfiltrated data rides.',
  evaluate(ctx) {
    if (!ctx.request.output) return [];
    const { defanged } = defangLinks(stripHidden(ctx.request.output), ctx.policy.rendering.linkAllowHosts);
    if (defanged.length === 0) return [];
    const hosts = [...new Set(defanged.map((d) => d.host))];
    return [{ target: 'output', message: `Defanged ${defanged.length} link(s) to unapproved host(s): ${hosts.join(', ')}.` }];
  },
};
