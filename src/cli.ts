/**
 * Operator CLI: the only way a secret value enters the vault. It prompts on
 * an interactive terminal with no echo. Values never come from arguments,
 * pipes or the environment of a tool call, and nothing here prints a value.
 *
 *   npm run vault -- add STRIPE_KEY              (Windows: DPAPI, the default)
 *   npm run vault -- add STRIPE_KEY --source credman --replace
 *   npm run vault -- link STRIPE_KEY --env STRIPE_LIVE_KEY
 *   npm run vault -- list | check | remove STRIPE_KEY
 */
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeCredman, deleteCredman, protectDpapi } from './windows.ts';
import { MIN_SECRET_LENGTH } from './redact.ts';
import { credmanTarget, loadVault, saveVault, SECRET_NAME, type SourceRef, vaultDirectory, vaultFilePath, withSecret, withoutSecret } from './store.ts';
import { resolveState } from './state.ts';

const USAGE = `usage:
  vault add NAME [--source dpapi|credman] [--replace]   prompt for the value (hidden), store it
  vault link NAME --env VARIABLE                         read NAME from an environment variable of Pi
  vault list                                             names and sources, no values
  vault check [NAME]                                     whether each value resolves, no values
  vault remove NAME                                      forget NAME (deletes a Credential Manager entry)
  vault path                                             where vault.json lives`;

export async function main(argv: readonly string[], io: { readonly out: (line: string) => void; readonly err: (line: string) => void } = defaultIo): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case 'add': return await add(rest, io);
      case 'link': return await link(rest, io);
      case 'list': return await list(io);
      case 'check': return await check(rest, io);
      case 'remove': return await remove(rest, io);
      case 'path': io.out(vaultFilePath(vaultDirectory())); return 0;
      default: io.err(USAGE); return 2;
    }
  } catch (error) {
    io.err(`vault: ${error instanceof Error ? error.message : 'failed'}`);
    return 1;
  }
}

const defaultIo = {
  out: (line: string) => process.stdout.write(`${line}\n`),
  err: (line: string) => process.stderr.write(`${line}\n`),
};

async function add(args: readonly string[], io: { readonly out: (line: string) => void }): Promise<number> {
  const name = nameArgument(args);
  const source = optionValue(args, '--source') ?? (process.platform === 'win32' ? 'dpapi' : undefined);
  if (source !== 'dpapi' && source !== 'credman') throw new Error('--source must be dpapi or credman (dpapi is the Windows default; both need Windows)');
  const dir = vaultDirectory();
  const loaded = await loadVault(dir);
  if (loaded.file.secrets[name] && !args.includes('--replace')) throw new Error(`${name} already exists; pass --replace to overwrite it`);

  const value = await readHidden(`Value for ${name} (input hidden, Enter to finish): `);
  if (value.length < MIN_SECRET_LENGTH) throw new Error(`the value is shorter than ${MIN_SECRET_LENGTH} characters and would not be masked safely`);

  let ref: SourceRef;
  if (source === 'dpapi') {
    ref = { source: 'dpapi', blob: await protectDpapi(value) };
  } else {
    const target = credmanTarget(name);
    await writeCredman(target, value);
    ref = { source: 'credman', target };
  }
  try {
    await saveVault(dir, withSecret(loaded.file, name, ref));
  } catch (error) {
    if (ref.source === 'credman') await deleteCredman(ref.target).catch(() => false);
    throw error;
  }
  io.out(`${name} stored (${source}). The value was not printed.`);
  return 0;
}

async function link(args: readonly string[], io: { readonly out: (line: string) => void }): Promise<number> {
  const name = nameArgument(args);
  const variable = optionValue(args, '--env');
  if (!variable || !/^[A-Za-z_][A-Za-z0-9_]{0,255}$/.test(variable)) throw new Error('usage: vault link NAME --env VARIABLE');
  const dir = vaultDirectory();
  const loaded = await loadVault(dir);
  if (loaded.file.secrets[name] && !args.includes('--replace')) throw new Error(`${name} already exists; pass --replace to overwrite it`);
  await saveVault(dir, withSecret(loaded.file, name, { source: 'env', variable }));
  io.out(`${name} linked to the environment variable ${variable}.`);
  return 0;
}

async function list(io: { readonly out: (line: string) => void }): Promise<number> {
  const loaded = await loadVault(vaultDirectory());
  const names = Object.entries(loaded.file.secrets);
  if (names.length === 0) io.out('no secrets stored');
  for (const [name, ref] of names) io.out(`${name}\t${ref.source}`);
  return 0;
}

async function check(args: readonly string[], io: { readonly out: (line: string) => void }): Promise<number> {
  const loaded = await loadVault(vaultDirectory());
  const state = await resolveState(loaded.file, process.env);
  const only = args[0];
  if (only !== undefined && !(only in loaded.file.secrets)) throw new Error(`${only} is not stored`);
  let failures = 0;
  for (const entry of state.entries) {
    if (only !== undefined && entry.name !== only) continue;
    const ready = state.values.some(value => value.name === entry.name);
    if (!ready) failures += 1;
    io.out(`${entry.name}\t${entry.source}\t${ready ? 'ready' : `unavailable (${state.unavailable.get(entry.name) ?? 'unknown'})`}`);
  }
  return failures === 0 ? 0 : 1;
}

async function remove(args: readonly string[], io: { readonly out: (line: string) => void }): Promise<number> {
  const name = nameArgument(args);
  const dir = vaultDirectory();
  const loaded = await loadVault(dir);
  const ref = loaded.file.secrets[name];
  if (!ref) throw new Error(`${name} is not stored`);
  if (ref.source === 'credman') await deleteCredman(ref.target);
  await saveVault(dir, withoutSecret(loaded.file, name));
  io.out(`${name} removed.`);
  return 0;
}

function nameArgument(args: readonly string[]): string {
  const name = args[0];
  if (!name || !SECRET_NAME.test(name)) throw new Error('the secret name must start with a letter or underscore and use only letters, digits and underscores (64 characters max)');
  return name;
}

function optionValue(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${flag} needs a value`);
  return value;
}

/** Reads one line from an interactive terminal without echo. Refuses pipes and non-interactive runs. */
export function readHidden(prompt: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY || !process.stdout.isTTY) {
    return Promise.reject(new Error('add needs an interactive terminal: the value is typed there and never taken from arguments or pipes'));
  }
  process.stdout.write(prompt);
  stdin.setRawMode(true);
  stdin.setEncoding('utf8');
  stdin.resume();
  return new Promise<string>((resolve, reject) => {
    let value = '';
    const finish = (error?: Error) => {
      stdin.off('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stdout.write('\n');
      if (error) reject(error);
      else resolve(value);
    };
    const onData = (chunk: string) => {
      for (const char of chunk) {
        if (char === '\r' || char === '\n') return finish();
        if (char === '\u0003') return finish(new Error('cancelled; nothing was stored'));
        if (char === '\u007f' || char === '\b') value = value.slice(0, -1);
        else if (char >= ' ') value += char;
      }
    };
    stdin.on('data', onData);
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; });
}
