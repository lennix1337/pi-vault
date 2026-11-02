import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveState } from '../src/state.ts';
import { EMPTY_VAULT, withSecret, type VaultFile } from '../src/store.ts';
import type { WindowsReadRequest, WindowsReadResult } from '../src/windows.ts';

function vault(secrets: VaultFile['secrets']): VaultFile {
  return { version: 1, secrets };
}

test('environment references resolve from the Pi environment; short or empty values are never injected', async () => {
  const file = vault({
    GOOD: { source: 'env', variable: 'PI_TEST_GOOD' },
    SHORT: { source: 'env', variable: 'PI_TEST_SHORT' },
    EMPTY: { source: 'env', variable: 'PI_TEST_EMPTY' },
    ABSENT: { source: 'env', variable: 'PI_TEST_ABSENT' },
  });
  const state = await resolveState(file, { PI_TEST_GOOD: 'FAKE-ENV-VALUE-0001', PI_TEST_SHORT: 'abc', PI_TEST_EMPTY: '' }, async () => new Map());
  assert.deepEqual(state.values, [{ name: 'GOOD', value: 'FAKE-ENV-VALUE-0001' }]);
  assert.equal(state.unavailable.get('SHORT'), 'too_short');
  assert.equal(state.unavailable.get('EMPTY'), 'missing');
  assert.equal(state.unavailable.get('ABSENT'), 'missing');
  assert.deepEqual(state.entries.find(entry => entry.name === 'GOOD'), { name: 'GOOD', source: 'env', variable: 'PI_TEST_GOOD' });
});

test('Windows references are decrypted in one batch; each outcome maps to its own name', async () => {
  const seen: WindowsReadRequest[][] = [];
  const file = withSecret(withSecret(EMPTY_VAULT, 'DP', { source: 'dpapi', blob: 'aa' }), 'CM', { source: 'credman', target: 'pi-vault:CM' });
  const reader = async (requests: readonly WindowsReadRequest[]) => {
    seen.push([...requests]);
    return new Map<string, WindowsReadResult>([
      ['DP', { ok: true, value: 'FAKE-DPAPI-VALUE-0002' }],
      ['CM', { ok: false, code: 'missing' }],
    ]);
  };
  const state = await resolveState(file, {}, reader);
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0]?.map(request => [request.name, request.source, request.locator]), [['DP', 'dpapi', 'aa'], ['CM', 'credman', 'pi-vault:CM']]);
  assert.deepEqual(state.values, [{ name: 'DP', value: 'FAKE-DPAPI-VALUE-0002' }]);
  assert.equal(state.unavailable.get('CM'), 'missing');
});

test('a reader failure leaves Windows secrets unavailable instead of failing the whole vault', async () => {
  const file = withSecret(EMPTY_VAULT, 'DP', { source: 'dpapi', blob: 'aa' });
  const state = await resolveState(file, {}, async () => { throw new Error('boom'); });
  assert.equal(state.values.length, 0);
  assert.equal(state.unavailable.get('DP'), 'unsupported');
});
