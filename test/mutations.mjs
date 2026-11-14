import { mkdtempSync, cpSync, readFileSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';

const root = fileURLToPath(new URL('../', import.meta.url));
const cases = [
  ['encoded-mask', 'src/redact.ts', "[value, Buffer.from(value, 'utf8').toString('base64')]", '[value]', 'stored value is masked in raw and base64', 'redact'],
  ['embedded-base64', 'src/redact.ts', '[...variants, ...embeddedBase64(value)]', 'variants', 'inside a longer base64 payload', 'redact'],
  ['embedded-min-length', 'src/redact.ts', '.filter(stretch => stretch.length >= MIN_EMBEDDED_BASE64_LENGTH)', '', 'too short for a safe stretch', 'redact'],
  ['stdout-mask', 'src/vault-run.ts', "redactText(result.stdout.toString('utf8'), state.values)", "result.stdout.toString('utf8')", 'placeholder form injects', 'vault-run'],
  ['stderr-mask', 'src/vault-run.ts', "redactText(result.stderr.toString('utf8'), state.values)", "result.stderr.toString('utf8')", 'failing command reports', 'vault-run'],
  ['placeholder-grant', 'src/vault-run.ts', 'names.add(name);', '', 'placeholder becomes a shell reference', 'vault-run'],
  ['unknown-name', 'src/vault-run.ts', 'if (!state.entries.some(entry => entry.name === name))', 'if (false)', 'unknown or unavailable secret', 'vault-run'],
  ['carrier-scrub', 'src/vault-run.ts', 'if (carriers.has(key.toUpperCase())) delete env[key];', 'if (false) delete env[key];', 'environment carriers are removed', 'vault-run'],
  ['literal-refusal', 'src/vault-run.ts', 'if (leaks.length > 0) return refused(describeLeaks(leaks));', 'if (false) return refused(describeLeaks(leaks));', 'refusal of a literal secret in the command', 'vault-run'],
  ['list-values', 'src/index.ts', 'name: entry.name,', 'name: entry.name, value: state.values.find(value => value.name === entry.name)?.value,', 'vault_list reports names', 'extension'],
];
let killed = 0;
let failed = false;
for (const [name, file, before, after, pattern, test] of cases) {
  const dir = mkdtempSync(join(tmpdir(), 'pi-vault-mutant-'));
  try {
    cpSync(join(root, 'src'), join(dir, 'src'), { recursive: true });
    cpSync(join(root, 'test'), join(dir, 'test'), { recursive: true });
    cpSync(join(root, 'package.json'), join(dir, 'package.json'));
    symlinkSync(resolve(root, 'node_modules'), join(dir, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
    const path = join(dir, file);
    const source = readFileSync(path, 'utf8');
    assert.equal(source.split(before).length, 2, `unique mutation ${name}`);
    writeFileSync(path, source.replace(before, after));
    const result = spawnSync(process.execPath, ['--import', 'tsx', '--test', `--test-name-pattern=${pattern}`, `test/${test}.test.ts`], { cwd: dir, encoding: 'utf8', timeout: 30000 });
    assert.equal(result.error, undefined, `${name}: process must run, not time out`);
    if (result.status === 0) {
      console.log(`${name}: survived`);
      failed = true;
      continue;
    }
    assert.match(result.stdout + result.stderr, /AssertionError/, `${name}: must fail an assertion, not crash`);
    killed++;
    console.log(`${name}: killed by assertion`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
console.log(`${killed}/${cases.length} guard mutants killed; disposable copies only`);
if (failed) process.exitCode = 1;
