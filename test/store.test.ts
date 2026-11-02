import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, rmSync, writeFileSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createVaultRuntime } from '../src/state.ts';
import { loadVault, parseVaultFile, saveVault, vaultFilePath, withSecret, withoutSecret, EMPTY_VAULT } from '../src/store.ts';

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'pi-vault-store-'));
}

test('the vault file accepts exactly the three reference kinds and nothing else', () => {
  const ok = parseVaultFile(JSON.stringify({
    version: 1,
    secrets: {
      STRIPE_KEY: { source: 'dpapi', blob: '0100000000ab' },
      GITHUB_TOKEN: { source: 'credman', target: 'pi-vault:GITHUB_TOKEN' },
      LEGACY: { source: 'env', variable: 'LEGACY_TOKEN' },
    },
  }));
  assert.deepEqual(Object.keys(ok.secrets).sort(), ['GITHUB_TOKEN', 'LEGACY', 'STRIPE_KEY']);

  const bad: unknown[] = [
    { version: 2, secrets: {} },
    { version: 1, secrets: {}, extra: true },
    { version: 1, secrets: { 'bad-name': { source: 'env', variable: 'X' } } },
    { version: 1, secrets: { A: { source: 'plain', value: 'x' } } },
    { version: 1, secrets: { A: { source: 'dpapi', blob: 'not-hex!' } } },
    { version: 1, secrets: { A: { source: 'dpapi', blob: 'ab', value: 'FAKE-PLAIN-VALUE' } } },
    { version: 1, secrets: { A: { source: 'credman', target: 'has space' } } },
    { version: 1, secrets: { A: { source: 'env', variable: '1BAD' } } },
  ];
  for (const candidate of bad) {
    assert.throws(() => parseVaultFile(JSON.stringify(candidate)), /vault\.json/, JSON.stringify(candidate));
  }
});

test('a rejected file never echoes its contents in the error', () => {
  const marker = 'FAKE-MARKER-VALUE-9999';
  assert.throws(() => parseVaultFile(`{"version":1,"secrets":{"A":{"source":"env","variable":"${marker}!"}}}`), error => {
    assert.equal(String(error).includes(marker), false);
    return true;
  });
  assert.throws(() => parseVaultFile(`not json ${marker}`), error => String(error).includes(marker) === false);
});

test('save and load round-trip; a missing file is an empty vault; writes leave no temporary files', async () => {
  const dir = tempDir();
  try {
    assert.deepEqual((await loadVault(dir)).file, EMPTY_VAULT);
    const file = withSecret(EMPTY_VAULT, 'STRIPE_KEY', { source: 'dpapi', blob: 'abcdef' });
    await saveVault(dir, file);
    const loaded = await loadVault(dir);
    assert.deepEqual(loaded.file, file);
    assert.ok(loaded.mtimeMs > 0);
    assert.deepEqual(readdirSync(dir).sort(), ['vault.json']);
    await saveVault(dir, withoutSecret(file, 'STRIPE_KEY'));
    assert.deepEqual((await loadVault(dir)).file.secrets, {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the runtime reloads when vault.json changes, so a new secret needs no restart', async () => {
  const dir = tempDir();
  try {
    const env = { PI_TEST_VAULT_VALUE: 'FAKE-RELOAD-VALUE-0001' };
    const runtime = createVaultRuntime({ dir, env, readWindows: async () => new Map() });
    assert.deepEqual((await runtime.state()).values, []);

    await saveVault(dir, withSecret(EMPTY_VAULT, 'RELOADED', { source: 'env', variable: 'PI_TEST_VAULT_VALUE' }));
    utimesSync(vaultFilePath(dir), new Date(2_000_000_000_000), new Date(2_000_000_000_000));
    assert.deepEqual((await runtime.state()).values.map(value => value.name), ['RELOADED']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an unreadable vault is reported as a file error and never as a crash', async () => {
  const dir = tempDir();
  try {
    writeFileSync(vaultFilePath(dir), '{"version":1,"secrets":{"A":{"source":"plain"}}}');
    const state = await createVaultRuntime({ dir, env: {}, readWindows: async () => new Map() }).state();
    assert.match(state.fileError ?? '', /not a valid env, dpapi or credman reference/);
    assert.deepEqual(state.values, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
