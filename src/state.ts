/**
 * Resolves the vault's references into values, in memory, for this Pi process.
 * Values are never written anywhere: not to vault.json, logs or tool results.
 */
import { stat } from 'node:fs/promises';
import { MIN_SECRET_LENGTH, type KnownSecret } from './redact.ts';
import { loadVault, type SourceKind, type VaultFile, vaultFilePath } from './store.ts';
import { readWindowsSecrets, type WindowsReadRequest, type WindowsReadResult } from './windows.ts';

export type UnavailableCode = 'missing' | 'too_short' | 'decrypt' | 'unsupported' | 'unavailable';

export interface SecretEntry {
  readonly name: string;
  readonly source: SourceKind;
  /** Environment variable of the Pi process that carries the value (env sources only). */
  readonly variable?: string;
}

export interface SecretState {
  readonly entries: readonly SecretEntry[];
  /** Values that can be injected and masked. */
  readonly values: readonly KnownSecret[];
  /** Declared secrets whose value could not be resolved, by reason code. */
  readonly unavailable: ReadonlyMap<string, UnavailableCode>;
  /** Set when vault.json itself is unreadable: nothing can be injected, and value-based masking is absent. */
  readonly fileError?: string;
}

export type WindowsReader = (requests: readonly WindowsReadRequest[]) => Promise<Map<string, WindowsReadResult>>;

export async function resolveState(file: VaultFile, env: NodeJS.ProcessEnv, readWindows: WindowsReader = readWindowsSecrets): Promise<SecretState> {
  const entries: SecretEntry[] = [];
  const values: KnownSecret[] = [];
  const unavailable = new Map<string, UnavailableCode>();
  const windowsRequests: WindowsReadRequest[] = [];

  for (const [name, ref] of Object.entries(file.secrets)) {
    if (ref.source === 'env') {
      entries.push({ name, source: 'env', variable: ref.variable });
      accept(name, env[ref.variable], unavailable, values, 'too_short');
    } else if (ref.source === 'dpapi') {
      entries.push({ name, source: 'dpapi' });
      windowsRequests.push({ name, source: 'dpapi', locator: ref.blob });
    } else {
      entries.push({ name, source: 'credman' });
      windowsRequests.push({ name, source: 'credman', locator: ref.target });
    }
  }

  if (windowsRequests.length > 0) {
    let results: Map<string, WindowsReadResult>;
    try {
      results = await readWindows(windowsRequests);
    } catch {
      results = new Map(windowsRequests.map(request => [request.name, { ok: false, code: 'unsupported' } as const]));
    }
    for (const request of windowsRequests) {
      const result = results.get(request.name);
      if (!result) unavailable.set(request.name, 'unavailable');
      else if (result.ok) accept(request.name, result.value, unavailable, values, 'too_short');
      else unavailable.set(request.name, result.code);
    }
  }

  return { entries: entries.sort((a, b) => a.name.localeCompare(b.name)), values, unavailable };
}

function accept(name: string, value: string | undefined, unavailable: Map<string, UnavailableCode>, values: KnownSecret[], shortCode: UnavailableCode): void {
  if (value === undefined || value === '') {
    unavailable.set(name, 'missing');
  } else if (value.length < MIN_SECRET_LENGTH) {
    unavailable.set(name, shortCode);
  } else {
    values.push({ name, value });
  }
}

export interface VaultRuntime {
  /** Current state. Reloads when vault.json changes on disk, so `pi-vault add` takes effect without a restart. */
  state(): Promise<SecretState>;
}

export function createVaultRuntime(options: { readonly dir: string; readonly env?: NodeJS.ProcessEnv; readonly readWindows?: WindowsReader }): VaultRuntime {
  const env = options.env ?? process.env;
  let cached: { readonly mtimeMs: number; readonly promise: Promise<SecretState> } | undefined;

  async function loadState(): Promise<SecretState> {
    try {
      const loaded = await loadVault(options.dir);
      return await resolveState(loaded.file, env, options.readWindows);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'vault could not be loaded';
      return { entries: [], values: [], unavailable: new Map(), fileError: message };
    }
  }

  return {
    async state() {
      const mtimeMs = await stat(vaultFilePath(options.dir)).then(info => info.mtimeMs, () => 0);
      if (!cached || cached.mtimeMs !== mtimeMs) cached = { mtimeMs, promise: loadState() };
      return cached.promise;
    },
  };
}
