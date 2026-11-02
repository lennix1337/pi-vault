/**
 * The vault_run core: decides whether a command may run, injects the granted
 * secrets into that one child process, and masks the output before it is returned.
 */
import { runShell } from './process.ts';
import { findLeaks, type KnownSecret, mapStrings, redactText } from './redact.ts';
import type { SecretState } from './state.ts';

export const DEFAULT_TIMEOUT_MS = 120_000;
export const MAX_TIMEOUT_MS = 600_000;
/** Characters of each stream returned to the model; the full capture is redacted before this cut. */
export const DISPLAY_LIMIT_CHARS = 16_000;

const PLACEHOLDER = /\{\{secret:([A-Za-z_][A-Za-z0-9_]{0,63})\}\}/g;

export interface VaultRunRequest {
  readonly command: string;
  readonly secrets?: readonly string[];
  readonly timeoutMs?: number;
}

export interface VaultRunReport {
  readonly status: 'ok' | 'failed' | 'timeout' | 'aborted' | 'error' | 'refused';
  readonly exitCode: number | null;
  /** Names only. */
  readonly injected: readonly string[];
  readonly stdout: string;
  readonly stderr: string;
  readonly truncated: boolean;
  /** Why the command did not run. Names and shapes only, never values. */
  readonly reason?: string;
}

/** `{{secret:NAME}}` becomes `${NAME}`: the shell reads the value from its environment, the text never holds it. */
export function expandPlaceholders(command: string): { readonly command: string; readonly names: readonly string[] } {
  const names = new Set<string>();
  const expanded = command.replace(PLACEHOLDER, (_match, name: string) => {
    names.add(name);
    return `\${${name}}`;
  });
  return { command: expanded, names: [...names] };
}

/** Stored values and token shapes found in any string of a tool call's arguments. */
export function argumentLeaks(input: unknown, state: SecretState): string[] {
  const labels = new Set<string>();
  mapStrings(input, text => {
    for (const label of findLeaks(text, state.values)) labels.add(label);
    return text;
  });
  return [...labels];
}

export function describeLeaks(labels: readonly string[]): string {
  return `argument contains a stored secret or a token shape (${labels.join(', ')}); write {{secret:NAME}} instead of a value`;
}

export async function runVault(request: VaultRunRequest, options: { readonly cwd: string; readonly state: SecretState; readonly signal?: AbortSignal; readonly baseEnv?: NodeJS.ProcessEnv }): Promise<VaultRunReport> {
  const { state } = options;
  if (state.fileError) return refused(`vault unavailable: ${state.fileError}`);

  const leaks = findLeaks(request.command, state.values);
  if (leaks.length > 0) return refused(describeLeaks(leaks));

  const expanded = expandPlaceholders(request.command);
  const granted = [...new Set([...(request.secrets ?? []), ...expanded.names])];
  const injected: KnownSecret[] = [];
  for (const name of granted) {
    if (!state.entries.some(entry => entry.name === name)) return refused(`unknown secret ${name}`);
    const value = state.values.find(secret => secret.name === name);
    if (!value) return refused(`secret ${name} is unavailable (${state.unavailable.get(name) ?? 'unavailable'})`);
    injected.push(value);
  }

  const timeoutMs = Math.min(Math.max(request.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1_000), MAX_TIMEOUT_MS);
  const result = await runShell({
    command: expanded.command,
    cwd: options.cwd,
    env: childEnvironment(options.baseEnv ?? process.env, state, injected),
    timeoutMs,
    signal: options.signal,
  });

  const stdout = bound(redactText(result.stdout.toString('utf8'), state.values));
  const stderr = bound(redactText(result.stderr.toString('utf8'), state.values));
  return {
    status: result.status,
    exitCode: result.exitCode,
    injected: granted,
    stdout: stdout.text,
    stderr: stderr.text,
    truncated: result.truncated || stdout.cut || stderr.cut,
  };
}

/**
 * The child's environment: the Pi environment without any variable that
 * carries a vault value, plus the granted values. Other secrets stay out.
 */
export function childEnvironment(base: NodeJS.ProcessEnv, state: SecretState, injected: readonly KnownSecret[]): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base };
  const carriers = new Set(state.entries.flatMap(entry => (entry.variable ? [entry.variable.toUpperCase()] : [])));
  for (const key of Object.keys(env)) if (carriers.has(key.toUpperCase())) delete env[key];
  for (const secret of injected) env[secret.name] = secret.value;
  return env;
}

/**
 * Shell text that removes, from a bash or PowerShell command, the environment
 * variables that carry vault values, so the model's own commands cannot print them.
 */
export function scrubPrefix(shell: 'bash' | 'powershell', state: SecretState): string {
  const variables = [...new Set(state.entries.flatMap(entry => (entry.variable ? [entry.variable] : [])))];
  if (variables.length === 0) return '';
  if (shell === 'bash') return `unset -v ${variables.join(' ')} 2>/dev/null; `;
  return `Remove-Item -ErrorAction SilentlyContinue -Path ${variables.map(name => `Env:${name}`).join(',')}; `;
}

function bound(text: string): { readonly text: string; readonly cut: boolean } {
  return text.length > DISPLAY_LIMIT_CHARS ? { text: text.slice(0, DISPLAY_LIMIT_CHARS), cut: true } : { text, cut: false };
}

function refused(reason: string): VaultRunReport {
  return { status: 'refused', exitCode: null, injected: [], stdout: '', stderr: '', truncated: false, reason };
}
