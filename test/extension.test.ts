import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import extension from '../src/index.ts';
import { createVaultRuntime } from '../src/state.ts';
import { EMPTY_VAULT, saveVault, withSecret } from '../src/store.ts';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const VALUE = 'FAKE-EXT-VALUE-5521';
const LIVE = ['rk', 'live', 'TESTONLY9876'].join('_');

type Handler = (event: any, ctx?: any) => Promise<any> | any;

async function harness() {
  const handlers = new Map<string, Handler[]>();
  const tools = new Map<string, any>();
  const pi = {
    on(name: string, handler: Handler) { handlers.set(name, [...(handlers.get(name) ?? []), handler]); return () => undefined; },
    registerTool(definition: any) { tools.set(definition.name, definition); },
  } as unknown as ExtensionAPI;
  const dir = mkdtempSync(join(tmpdir(), 'pi-vault-ext-'));
  const file = withSecret(EMPTY_VAULT, 'STRIPE_KEY', { source: 'env', variable: 'PI_TEST_EXT_STRIPE' });
  await saveVault(dir, file);
  const runtime = createVaultRuntime({ dir, env: { PI_TEST_EXT_STRIPE: VALUE }, readWindows: async () => new Map() });
  extension(pi, { runtime });
  const call = async (name: string, event: any): Promise<any> => {
    let last: unknown;
    for (const handler of handlers.get(name) ?? []) last = await handler(event, {});
    return last;
  };
  return { tools, call, dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('the extension registers vault_run and vault_list and the three hooks', async () => {
  const { tools, cleanup } = await harness();
  try {
    assert.deepEqual([...tools.keys()].sort(), ['vault_list', 'vault_run']);
  } finally {
    cleanup();
  }
});

test('tool_call refuses a literal stored value or a live token in any tool argument, before the tool runs', async () => {
  const { call, cleanup } = await harness();
  try {
    const bash = await call('tool_call', { type: 'tool_call', toolCallId: '1', toolName: 'bash', input: { command: `echo ${VALUE}` } });
    assert.equal(bash.block, true);
    assert.match(bash.reason, /STRIPE_KEY/);
    assert.equal(bash.reason.includes(VALUE), false);
    const write = await call('tool_call', { type: 'tool_call', toolCallId: '2', toolName: 'write', input: { path: 'x.txt', content: LIVE } });
    assert.equal(write.block, true);
    assert.match(write.reason, /stripe-live-key/);
  } finally {
    cleanup();
  }
});

test('tool_call lets placeholders through and prefixes bash commands so carrier variables are unset', async () => {
  const { call, cleanup } = await harness();
  try {
    const input = { command: 'echo "{{secret:STRIPE_KEY}}"' };
    const result = await call('tool_call', { type: 'tool_call', toolCallId: '3', toolName: 'bash', input });
    assert.equal(result, undefined);
    assert.equal(input.command, 'unset -v PI_TEST_EXT_STRIPE 2>/dev/null; echo "{{secret:STRIPE_KEY}}"');
  } finally {
    cleanup();
  }
});

test('tool_result masks stored values, base64 and token shapes in text and in details; clean results pass unchanged', async () => {
  const { call, cleanup } = await harness();
  try {
    const b64 = Buffer.from(VALUE, 'utf8').toString('base64');
    const dirty = await call('tool_result', {
      type: 'tool_result', toolCallId: '4', toolName: 'read', input: {}, isError: false,
      content: [{ type: 'text', text: `secret=${VALUE} enc=${b64} key=${LIVE}` }],
      details: { preview: `head ${VALUE}`, nested: [LIVE] },
    });
    assert.deepEqual(dirty.content, [{ type: 'text', text: 'secret=[REDACTED:STRIPE_KEY] enc=[REDACTED:STRIPE_KEY] key=[REDACTED:stripe-live-key]' }]);
    assert.deepEqual(dirty.details, { preview: 'head [REDACTED:STRIPE_KEY]', nested: ['[REDACTED:stripe-live-key]'] });
    assert.equal(JSON.stringify(dirty).includes(VALUE), false);

    const clean = await call('tool_result', { type: 'tool_result', toolCallId: '5', toolName: 'read', input: {}, isError: false, content: [{ type: 'text', text: 'nothing here' }], details: { n: 1 } });
    assert.equal(clean, undefined);
  } finally {
    cleanup();
  }
});

test('vault_run executes through the tool, returns masked output and never the value', async () => {
  const { tools, cleanup } = await harness();
  try {
    const tool = tools.get('vault_run');
    const result = await tool.execute('t1', { command: 'printf "%s" "{{secret:STRIPE_KEY}}"' }, undefined, undefined, { cwd: tmpdir() });
    assert.equal(result.isError, false);
    const text = result.content[0].text as string;
    assert.equal(text.includes(VALUE), false);
    assert.equal(JSON.parse(text).stdout, '[REDACTED:STRIPE_KEY]');

    const refused = await tool.execute('t2', { command: `echo ${VALUE}` }, undefined, undefined, { cwd: tmpdir() });
    assert.equal(refused.isError, true);
    assert.equal(JSON.parse(refused.content[0].text).status, 'refused');
  } finally {
    cleanup();
  }
});

test('vault_list reports names, sources and readiness, never values', async () => {
  const { tools, cleanup } = await harness();
  try {
    const result = await tools.get('vault_list').execute('t3', {}, undefined, undefined, {});
    const text = result.content[0].text as string;
    assert.equal(text.includes(VALUE), false);
    assert.deepEqual(JSON.parse(text).secrets, [{ name: 'STRIPE_KEY', source: 'env', state: 'ready' }]);
  } finally {
    cleanup();
  }
});
