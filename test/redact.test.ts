import assert from 'node:assert/strict';
import { test } from 'node:test';
import { findLeaks, mapStrings, redactText, valueVariants } from '../src/redact.ts';

// Fixtures are assembled at runtime so no literal token-shaped string sits in the repository.
const liveKey = ['sk', 'live', 'TESTONLY1234'].join('_');
const restrictedKey = ['rk', 'live', 'TESTONLY5678'].join('_');
const githubToken = ['gh', 'p_', 'TESTONLY0123456789abcd'].join('');
const awsKey = ['AK', 'IA', 'TESTONLY000000AB'].join('');
const jwt = ['eyJ', 'hbGciOiJIUzI1NiJ9', '.', 'eyJzdWIiOiJ0ZXN0In0', '.', 'signaturePart1'].join('');
const stored = { name: 'STRIPE_KEY', value: 'FAKE-STORED-VALUE-0001' };

test('stored value is masked in raw and base64 form, and the marker names the secret, never the value', () => {
  const b64 = Buffer.from(stored.value, 'utf8').toString('base64');
  const text = `raw=${stored.value} encoded=${b64} again=${stored.value}`;
  const out = redactText(text, [stored]);
  assert.equal(out, 'raw=[REDACTED:STRIPE_KEY] encoded=[REDACTED:STRIPE_KEY] again=[REDACTED:STRIPE_KEY]');
  assert.equal(out.includes(stored.value), false);
  assert.equal(out.includes(b64), false);
});

test('known token shapes are masked even when no secret is stored', () => {
  const slackToken = ['xox', 'b-TESTONLY-1234567'].join('');
  const webhookSecret = ['whsec', 'TESTONLY1234'].join('_');
  const text = [liveKey, restrictedKey, githubToken, awsKey, jwt, slackToken, webhookSecret].join(' ');
  const out = redactText(text, []);
  for (const label of ['stripe-live-key', 'github-token', 'aws-access-key', 'jwt', 'slack-token', 'stripe-webhook-secret']) {
    assert.ok(out.includes(`[REDACTED:${label}]`), label);
  }
  for (const token of [liveKey, restrictedKey, githubToken, awsKey, jwt]) assert.equal(out.includes(token), false);
});

test('private key blocks are masked from BEGIN to END', () => {
  const block = ['-----BEGIN ' + 'RSA PRIVATE KEY-----', 'MIIBOgIBAAJBAKj', '-----END ' + 'RSA PRIVATE KEY-----'].join('\n');
  assert.equal(redactText(`before\n${block}\nafter`, []), 'before\n[REDACTED:private-key]\nafter');
});

test('a value is found whole even when it contains a shorter stored value', () => {
  const secrets = [{ name: 'SHORT', value: 'FAKE-SHORT-0001' }, { name: 'LONG', value: 'FAKE-SHORT-0001-SUFFIX' }];
  assert.equal(redactText('x FAKE-SHORT-0001-SUFFIX y', secrets), 'x [REDACTED:LONG] y');
});

test('findLeaks reports names and shape labels without the matched text', () => {
  const leaks = findLeaks(`curl -H "Authorization: ${stored.value}" ${liveKey}`, [stored]);
  assert.deepEqual(leaks.sort(), ['STRIPE_KEY', 'stripe-live-key'].sort());
  assert.deepEqual(findLeaks('echo {{secret:STRIPE_KEY}} and $STRIPE_KEY', [stored]), []);
  assert.deepEqual(findLeaks('plain text', [stored]), []);
});

test('mapStrings masks nested strings and copies structure without touching other values', () => {
  const input = { a: `v=${stored.value}`, list: [stored.value, 3, null, { deep: `x ${liveKey}` }], flag: true };
  const out = mapStrings(input, text => redactText(text, [stored]));
  assert.deepEqual(out, { a: 'v=[REDACTED:STRIPE_KEY]', list: ['[REDACTED:STRIPE_KEY]', 3, null, { deep: 'x [REDACTED:stripe-live-key]' }], flag: true });
  assert.equal(input.a.includes(stored.value), true, 'the original is not mutated');
});

test('variants are the raw value and its base64 form, longest first', () => {
  const variants = valueVariants('FAKE-SECRET-XYZ');
  assert.equal(variants.length, 2);
  assert.equal(variants[0], Buffer.from('FAKE-SECRET-XYZ', 'utf8').toString('base64'));
});
