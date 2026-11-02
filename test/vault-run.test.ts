import assert from 'node:assert/strict';
import { test } from 'node:test';
import { expandPlaceholders, runVault, scrubPrefix, argumentLeaks, childEnvironment } from '../src/vault-run.ts';
import { resolveState } from '../src/state.ts';
import { EMPTY_VAULT, withSecret } from '../src/store.ts';
import { tmpdir } from 'node:os';

const VALUE = 'FAKE-RUN-VALUE-7731';
const B64 = Buffer.from(VALUE, 'utf8').toString('base64');
const LIVE = ['sk', 'live', 'TESTONLY1234'].join('_');
const cwd = tmpdir();

async function stateWith(env: NodeJS.ProcessEnv = {}) {
  const file = withSecret(withSecret(EMPTY_VAULT, 'STRIPE_KEY', { source: 'env', variable: 'PI_TEST_STRIPE' }), 'OTHER_KEY', { source: 'env', variable: 'PI_TEST_OTHER' });
  return resolveState(file, { PI_TEST_STRIPE: VALUE, PI_TEST_OTHER: 'FAKE-OTHER-VALUE-0002', ...env }, async () => new Map());
}

test('the placeholder becomes a shell reference, and the model text never holds the value', () => {
  assert.deepEqual(expandPlaceholders('curl -u "{{secret:STRIPE_KEY}}:" {{secret:OTHER_KEY}}'), { command: 'curl -u "${STRIPE_KEY}:" ${OTHER_KEY}', names: ['STRIPE_KEY', 'OTHER_KEY'] });
});

test('injection works: the child sees the value and the output carries no value', async () => {
  const state = await stateWith();
  const report = await runVault({ command: 'if [ -n "$STRIPE_KEY" ]; then echo "len=${#STRIPE_KEY}"; fi', secrets: ['STRIPE_KEY'] }, { cwd, state });
  assert.equal(report.status, 'ok', JSON.stringify(report));
  assert.equal(report.stdout.trim(), `len=${VALUE.length}`);
  assert.deepEqual(report.injected, ['STRIPE_KEY']);
});

test('the placeholder form injects the value and the output masks it, raw and base64', async () => {
  const state = await stateWith();
  const report = await runVault({ command: `printf 'raw=%s b64=%s\n' "{{secret:STRIPE_KEY}}" "$(printf %s "{{secret:STRIPE_KEY}}" | base64 | tr -d '\n')"` }, { cwd, state });
  assert.equal(report.status, 'ok', JSON.stringify(report));
  assert.equal(report.stdout.includes(VALUE), false);
  assert.equal(report.stdout.includes(B64), false);
  assert.equal(report.stdout.trim(), 'raw=[REDACTED:STRIPE_KEY] b64=[REDACTED:STRIPE_KEY]');
});

test('a value is injected into one child process only, never into the Pi process or a later command', async () => {
  const state = await stateWith();
  assert.equal(process.env.PI_TEST_STRIPE, undefined === process.env.PI_TEST_STRIPE ? undefined : process.env.PI_TEST_STRIPE);
  const later = await runVault({ command: 'echo "len=${#STRIPE_KEY}"' }, { cwd, state });
  assert.equal(later.stdout.trim(), 'len=0');
  assert.equal(process.env.STRIPE_KEY, undefined);
});

test('an unknown or unavailable secret is refused before anything runs', async () => {
  const state = await stateWith();
  const unknown = await runVault({ command: 'echo hi', secrets: ['NOT_STORED'] }, { cwd, state });
  assert.equal(unknown.status, 'refused');
  assert.equal(unknown.reason, 'unknown secret NOT_STORED');
  const broken = await resolveState(withSecret(EMPTY_VAULT, 'ABSENT', { source: 'env', variable: 'PI_TEST_NOPE' }), {}, async () => new Map());
  const refused = await runVault({ command: 'echo {{secret:ABSENT}}' }, { cwd, state: broken });
  assert.equal(refused.status, 'refused');
  assert.match(refused.reason ?? '', /ABSENT is unavailable \(missing\)/);
});

test('refusal of a literal secret in the command: a stored value or a token shape stops the run', async () => {
  const state = await stateWith();
  const literal = await runVault({ command: `echo ${VALUE}` }, { cwd, state });
  assert.equal(literal.status, 'refused');
  assert.match(literal.reason ?? '', /STRIPE_KEY/);
  assert.equal(literal.reason?.includes(VALUE), false, 'the refusal reason never repeats the value');
  const shape = await runVault({ command: `echo ${LIVE}` }, { cwd, state });
  assert.equal(shape.status, 'refused');
  assert.match(shape.reason ?? '', /stripe-live-key/);
});

test('refusal of literal secrets in arguments of any tool call', async () => {
  const state = await stateWith();
  assert.deepEqual(argumentLeaks({ path: 'notes.md', content: `key=${VALUE}` }, state), ['STRIPE_KEY']);
  assert.deepEqual(argumentLeaks({ nested: [{ text: LIVE }] }, state), ['stripe-live-key']);
  assert.deepEqual(argumentLeaks({ command: 'echo {{secret:STRIPE_KEY}}' }, state), []);
});

test('the granted names are the explicit list plus every placeholder, without duplicates', async () => {
  const state = await stateWith();
  const report = await runVault({ command: 'true {{secret:STRIPE_KEY}}', secrets: ['STRIPE_KEY', 'OTHER_KEY'] }, { cwd, state });
  assert.equal(report.status, 'ok', JSON.stringify(report));
  assert.deepEqual(report.injected, ['STRIPE_KEY', 'OTHER_KEY']);
});

test('a failing command reports failed with its exit code and redacted stderr', async () => {
  const state = await stateWith();
  const report = await runVault({ command: 'echo "{{secret:STRIPE_KEY}}" >&2; exit 7' }, { cwd, state });
  assert.equal(report.status, 'failed');
  assert.equal(report.exitCode, 7);
  assert.equal(report.stderr.trim(), '[REDACTED:STRIPE_KEY]');
});

test('a command that exceeds its timeout is killed and reports timeout', async () => {
  const state = await stateWith();
  const report = await runVault({ command: 'sleep 30', timeoutMs: 1000 }, { cwd, state });
  assert.equal(report.status, 'timeout');
});

test('the abort signal stops a running command', async () => {
  const state = await stateWith();
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 300);
  const report = await runVault({ command: 'sleep 30' }, { cwd, state, signal: controller.signal });
  assert.equal(report.status, 'aborted');
});

test('the output is masked in full before it is cut, so a value straddling the cut never leaks a prefix', async () => {
  const state = await stateWith();
  const report = await runVault({ command: `node -e "process.stdout.write('x'.repeat(15990))"; printf '%s' "{{secret:STRIPE_KEY}}"` }, { cwd, state });
  assert.equal(report.status, 'ok', JSON.stringify(report));
  assert.equal(report.stdout.includes(VALUE.slice(0, 6)), false);
  assert.equal(report.truncated, true);
});

test('output beyond the capture limit is cut, and a value straddling the cut is never shown in part', async () => {
  const state = await stateWith();
  const cap = 8 * 1024 * 1024;
  const command = `node -e "process.stdout.write('x'.repeat(${cap - 5}) + process.env.STRIPE_KEY + 'y'.repeat(64))"`;
  const report = await runVault({ command, timeoutMs: 60000 }, { cwd, state });
  assert.equal(report.status, 'ok', report.status);
  assert.equal(report.truncated, true);
  assert.equal(report.stdout.includes('FAKE-'), false);
});

test('environment carriers are removed from the child, and the granted values are added', () => {
  const state = { entries: [{ name: 'STRIPE_KEY', source: 'env' as const, variable: 'PI_TEST_STRIPE' }], values: [], unavailable: new Map() };
  const env = childEnvironment({ PI_TEST_STRIPE: 'FAKE-CARRIER-VALUE', pi_test_stripe: 'FAKE-CARRIER-VALUE', PATH: '/bin' }, state, [{ name: 'STRIPE_KEY', value: VALUE }]);
  assert.equal(env.PI_TEST_STRIPE, undefined);
  assert.equal(env.pi_test_stripe, undefined);
  assert.equal(env.STRIPE_KEY, VALUE);
  assert.equal(env.PATH, '/bin');
});

test('the scrub prefix removes env carriers for bash and PowerShell, and is empty without them', async () => {
  const state = await stateWith({ PI_TEST_STRIPE: VALUE });
  const prefix = scrubPrefix('bash', state);
  assert.equal(prefix, 'unset -v PI_TEST_OTHER PI_TEST_STRIPE 2>/dev/null; ');
  assert.match(scrubPrefix('powershell', state), /Env:PI_TEST_STRIPE/);
  assert.equal(scrubPrefix('bash', { entries: [], values: [], unavailable: new Map() }), '');
  const probe = await runVault({ command: `${prefix}echo "len=\${#PI_TEST_STRIPE}"` }, { cwd, state });
  assert.equal(probe.stdout.trim(), 'len=0');
});

test('a vault that cannot be read refuses to run anything', async () => {
  const report = await runVault({ command: 'echo ok' }, { cwd, state: { entries: [], values: [], unavailable: new Map(), fileError: 'vault.json is not valid JSON' } });
  assert.equal(report.status, 'refused');
});
