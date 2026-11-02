import { type ExtensionAPI, isToolCallEventType } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';
import { createVaultRuntime, type SecretState, type VaultRuntime } from './state.ts';
import { redactText, mapStrings } from './redact.ts';
import { vaultDirectory } from './store.ts';
import { argumentLeaks, describeLeaks, runVault, scrubPrefix } from './vault-run.ts';

export default function extension(pi: ExtensionAPI, options: { readonly runtime?: VaultRuntime } = {}) {
  const runtime = options.runtime ?? createVaultRuntime({ dir: vaultDirectory() });

  pi.on('session_start', () => {
    void runtime.state().catch(() => undefined);
  });

  // Literal secrets never enter a tool call: refused, not rewritten, so the model learns the rule.
  // Bash and PowerShell commands also lose the variables that carry vault values before they run.
  pi.on('tool_call', async event => {
    const state = await runtime.state();
    const leaks = argumentLeaks(event.input, state);
    if (leaks.length > 0) return { block: true, reason: describeLeaks(leaks) };
    if (isToolCallEventType('bash', event) && typeof event.input.command === 'string') {
      event.input.command = scrubPrefix('bash', state) + event.input.command;
    } else if (event.toolName === 'powershell' && typeof event.input.command === 'string') {
      event.input.command = scrubPrefix('powershell', state) + event.input.command;
    }
    return undefined;
  });

  // Every tool result is masked before the model sees it, including reads and the output of other extensions.
  pi.on('tool_result', async event => {
    const state = await runtime.state();
    const redact = (text: string) => redactText(text, state.values);
    const content = event.content.map(part => (part.type === 'text' ? { ...part, text: redact(part.text) } : part));
    const details = mapStrings(event.details, redact);
    const structuredContent = event.structuredContent === undefined ? undefined : mapStrings(event.structuredContent, redact);
    const changed = JSON.stringify([content, details, structuredContent]) !== JSON.stringify([event.content, event.details, event.structuredContent]);
    if (!changed) return undefined;
    return {
      content,
      details,
      ...(structuredContent !== undefined ? { structuredContent } : {}),
    };
  });

  pi.registerTool({
    name: 'vault_run',
    label: 'Vault run',
    description: 'Run a shell command with named vault secrets injected as environment variables of that command only. Refer to a secret as {{secret:NAME}} (the shell sees ${NAME}), inside double quotes when it is an argument; never type a value. The output is masked before you see it. Use vault_list for the names available.',
    parameters: Type.Object({
      command: Type.String({ minLength: 1, maxLength: 32768, description: 'Shell command, bash syntax. Use {{secret:NAME}} wherever the secret value belongs.' }),
      secrets: Type.Optional(Type.Array(Type.String({ maxLength: 64 }), { maxItems: 16, description: 'Names to inject as environment variables, e.g. ["STRIPE_KEY"]. Names used in {{secret:NAME}} are injected automatically.' })),
      timeoutMs: Type.Optional(Type.Integer({ minimum: 1000, maximum: 600000, description: 'Default 120000.' })),
    }, { additionalProperties: false }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const state = await runtime.state();
      const report = await runVault(params, { cwd: ctx.cwd, state, signal });
      return {
        content: [{ type: 'text', text: JSON.stringify(report) }],
        details: report,
        isError: report.status !== 'ok',
      };
    },
  });

  pi.registerTool({
    name: 'vault_list',
    label: 'Vault list',
    description: 'List the vault secret names, where each value is kept and whether it resolves. Never returns values.',
    parameters: Type.Object({}, { additionalProperties: false }),
    async execute() {
      const state = await runtime.state();
      const report = summarize(state);
      return { content: [{ type: 'text', text: JSON.stringify(report) }], details: report, isError: state.fileError !== undefined };
    },
  });
}

function summarize(state: SecretState) {
  return {
    status: state.fileError ? 'unavailable' : 'ok',
    ...(state.fileError ? { reason: state.fileError } : {}),
    secrets: state.entries.map(entry => ({
      name: entry.name,
      source: entry.source,
      state: state.values.some(value => value.name === entry.name) ? 'ready' : `unavailable (${state.unavailable.get(entry.name) ?? 'unknown'})`,
    })),
  };
}
