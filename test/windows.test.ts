import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { deleteCredman, protectDpapi, readWindowsSecrets, writeCredman } from '../src/windows.ts';

const isWindows = process.platform === 'win32';

test('off Windows the native stores are unavailable and say so, never returning a value', async () => {
  if (isWindows) return;
  const results = await readWindowsSecrets([{ name: 'A', source: 'dpapi', locator: '00' }, { name: 'B', source: 'credman', locator: 'pi-vault:B' }]);
  assert.deepEqual(results.get('A'), { ok: false, code: 'unsupported' });
  assert.deepEqual(results.get('B'), { ok: false, code: 'unsupported' });
  await assert.rejects(protectDpapi('FAKE-PLATFORM-VALUE'), /only on Windows/);
  await assert.rejects(writeCredman('pi-vault:X', 'FAKE-PLATFORM-VALUE'), /only on Windows/);
});

test('DPAPI: the stored blob is not the plaintext, and it decrypts back to the exact value, including non-ASCII', { skip: !isWindows && 'Windows only' }, async () => {
  const value = 'FAKE-DPAPI-Çãé-0003 \u2603 line2';
  const blob = await protectDpapi(value);
  assert.match(blob, /^[0-9a-f]+$/i);
  assert.equal(blob.includes(Buffer.from('FAKE-DPAPI').toString('hex')), false);
  const results = await readWindowsSecrets([{ name: 'DP', source: 'dpapi', locator: blob }, { name: 'BAD', source: 'dpapi', locator: '0102' }]);
  assert.deepEqual(results.get('DP'), { ok: true, value });
  assert.deepEqual(results.get('BAD'), { ok: false, code: 'decrypt' });
});

test('Credential Manager: write, read back, delete; a missing entry is reported as missing', { skip: !isWindows && 'Windows only' }, async () => {
  const target = `pi-vault-test:${randomUUID()}`;
  const value = 'FAKE-CREDMAN-VALUE-0004 ünï';
  try {
    await writeCredman(target, value);
    const found = await readWindowsSecrets([{ name: 'CM', source: 'credman', locator: target }]);
    assert.deepEqual(found.get('CM'), { ok: true, value });
  } finally {
    assert.equal(await deleteCredman(target), true);
  }
  const gone = await readWindowsSecrets([{ name: 'CM', source: 'credman', locator: target }]);
  assert.deepEqual(gone.get('CM'), { ok: false, code: 'missing' });
  assert.equal(await deleteCredman(target), false);
});
