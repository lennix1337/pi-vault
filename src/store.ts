/**
 * The vault file: secret names mapped to where their values live. It holds
 * references and protected blobs only. Plaintext values never reach this file.
 */
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

export type SourceRef =
  | { readonly source: 'env'; readonly variable: string }
  | { readonly source: 'dpapi'; readonly blob: string }
  | { readonly source: 'credman'; readonly target: string };

export type SourceKind = SourceRef['source'];

export interface VaultFile {
  readonly version: 1;
  readonly secrets: Readonly<Record<string, SourceRef>>;
}

export const SECRET_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const ENV_VARIABLE = /^[A-Za-z_][A-Za-z0-9_]{0,255}$/;
const MAX_BLOB_HEX = 64 * 1024;
const CREDMAN_TARGET = /^[\x21-\x7e]{1,256}$/;

export const EMPTY_VAULT: VaultFile = { version: 1, secrets: {} };

export function vaultDirectory(env: NodeJS.ProcessEnv = process.env): string {
  return env.PI_VAULT_DIR || join(homedir(), '.pi-vault');
}

export function vaultFilePath(dir: string): string {
  return join(dir, 'vault.json');
}

export function parseVaultFile(text: string): VaultFile {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error('vault.json is not valid JSON');
  }
  if (!isRecord(raw) || Object.keys(raw).some(key => key !== 'version' && key !== 'secrets') || raw.version !== 1 || !isRecord(raw.secrets)) {
    throw new Error('vault.json must be {"version":1,"secrets":{...}}');
  }
  const secrets: Record<string, SourceRef> = {};
  for (const [name, entry] of Object.entries(raw.secrets)) {
    if (!SECRET_NAME.test(name)) throw new Error(`vault.json has an invalid secret name: ${JSON.stringify(name.slice(0, 80))}`);
    secrets[name] = parseSourceRef(name, entry);
  }
  return { version: 1, secrets };
}

function parseSourceRef(name: string, entry: unknown): SourceRef {
  if (!isRecord(entry)) throw new Error(`vault.json entry ${name} must be an object`);
  if (entry.source === 'env' && hasOnly(entry, ['source', 'variable']) && typeof entry.variable === 'string' && ENV_VARIABLE.test(entry.variable)) {
    return { source: 'env', variable: entry.variable };
  }
  if (entry.source === 'dpapi' && hasOnly(entry, ['source', 'blob']) && typeof entry.blob === 'string' && /^[0-9a-fA-F]+$/.test(entry.blob) && entry.blob.length <= MAX_BLOB_HEX) {
    return { source: 'dpapi', blob: entry.blob };
  }
  if (entry.source === 'credman' && hasOnly(entry, ['source', 'target']) && typeof entry.target === 'string' && CREDMAN_TARGET.test(entry.target)) {
    return { source: 'credman', target: entry.target };
  }
  throw new Error(`vault.json entry ${name} is not a valid env, dpapi or credman reference`);
}

export interface LoadedVault {
  readonly file: VaultFile;
  /** Modification time of vault.json in ms, 0 when the file does not exist yet. */
  readonly mtimeMs: number;
}

export async function loadVault(dir: string): Promise<LoadedVault> {
  const path = vaultFilePath(dir);
  let text: string;
  let mtimeMs: number;
  try {
    text = await readFile(path, 'utf8');
    mtimeMs = (await stat(path)).mtimeMs;
  } catch (error) {
    if (isNodeError(error) && error.code === 'ENOENT') return { file: EMPTY_VAULT, mtimeMs: 0 };
    throw new Error('vault.json could not be read');
  }
  return { file: parseVaultFile(text), mtimeMs };
}

/** Writes the file atomically (temporary file, then rename) so a crash never leaves a half-written vault. */
export async function saveVault(dir: string, file: VaultFile): Promise<void> {
  await mkdir(dir, { recursive: true });
  const path = vaultFilePath(dir);
  const temp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    await writeFile(temp, `${JSON.stringify(file, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    await chmod(temp, 0o600).catch(() => undefined);
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true });
    throw error;
  }
}

export function withSecret(file: VaultFile, name: string, ref: SourceRef): VaultFile {
  return { version: 1, secrets: { ...file.secrets, [name]: ref } };
}

export function withoutSecret(file: VaultFile, name: string): VaultFile {
  const secrets = { ...file.secrets };
  delete secrets[name];
  return { version: 1, secrets };
}

export function credmanTarget(name: string): string {
  return `pi-vault:${name}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasOnly(entry: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(entry).every(key => keys.includes(key));
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}
