import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { main } from '../src/cli.ts';

const cliPath = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (line: string) => out.push(line), err: (line: string) => err.push(line) }, out, err };
}

test('the CLI keeps its contract: usage errors exit 2, a bad name is refused, nothing prints a value', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pi-vault-cli-'));
  const previous = process.env.PI_VAULT_DIR;
  process.env.PI_VAULT_DIR = dir;
  try {
    const usage = capture();
    assert.equal(await main([], usage.io), 2);
    assert.match(usage.err.join('\n'), /usage:/);

    const badName = capture();
    assert.equal(await main(['link', 'bad-name', '--env', 'X'], badName.io), 1);
    assert.match(badName.err.join('\n'), /secret name/);

    const link = capture();
    assert.equal(await main(['link', 'STRIPE_KEY', '--env', 'PI_TEST_CLI_STRIPE'], link.io), 0);
    assert.equal(link.out[0], 'STRIPE_KEY linked to the environment variable PI_TEST_CLI_STRIPE.');
    assert.match(readFileSync(join(dir, 'vault.json'), 'utf8'), /"variable": "PI_TEST_CLI_STRIPE"/);

    const list = capture();
    await main(['list'], list.io);
    assert.deepEqual(list.out, ['STRIPE_KEY\tenv']);

    const missingEnv = capture();
    assert.equal(await main(['check'], missingEnv.io), 1);
    assert.equal(missingEnv.out[0], 'STRIPE_KEY\tenv\tunavailable (missing)');

    process.env.PI_TEST_CLI_STRIPE = 'FAKE-CLI-VALUE-0005';
    const ready = capture();
    assert.equal(await main(['check', 'STRIPE_KEY'], ready.io), 0);
    assert.equal(ready.out[0], 'STRIPE_KEY\tenv\tready');
    assert.equal(ready.out.join('\n').includes('FAKE-CLI-VALUE'), false);

    const removed = capture();
    assert.equal(await main(['remove', 'STRIPE_KEY'], removed.io), 0);
    assert.equal(await main(['remove', 'STRIPE_KEY'], capture().io), 1, 'removing twice is an error');
  } finally {
    if (previous === undefined) delete process.env.PI_VAULT_DIR;
    else process.env.PI_VAULT_DIR = previous;
    delete process.env.PI_TEST_CLI_STRIPE;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('add refuses to take a value from anything but an interactive terminal, and stores nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pi-vault-cli-tty-'));
  try {
    const run = spawnSync(process.execPath, ['--import', 'tsx', cliPath, 'add', 'STRIPE_KEY', '--source', 'credman'], {
      env: { ...process.env, PI_VAULT_DIR: dir }, input: 'FAKE-PIPED-VALUE-0006\n', encoding: 'utf8', timeout: 60_000,
    });
    assert.equal(run.status, 1, run.stderr);
    assert.match(run.stderr, /interactive terminal/);
    assert.equal(run.stdout.includes('FAKE-PIPED-VALUE'), false);
    assert.equal(run.stderr.includes('FAKE-PIPED-VALUE'), false);
    assert.throws(() => readFileSync(join(dir, 'vault.json')), /ENOENT/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the CLI runs as a real program: path prints where vault.json lives', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pi-vault-cli-path-'));
  try {
    const run = spawnSync(process.execPath, ['--import', 'tsx', cliPath, 'path'], { env: { ...process.env, PI_VAULT_DIR: dir }, encoding: 'utf8', timeout: 60_000 });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout.trim(), join(dir, 'vault.json'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
