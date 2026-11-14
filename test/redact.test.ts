import assert from 'node:assert/strict';
import { test } from 'node:test';
import { findLeaks, mapStrings, MIN_EMBEDDED_BASE64_LENGTH, MIN_SECRET_LENGTH, redactText, valueVariants } from '../src/redact.ts';

// Fixtures are assembled at runtime so no literal token-shaped string sits in the repository.
const liveKey = ['sk', 'live', 'TESTONLY1234'].join('_');
const restrictedKey = ['rk', 'live', 'TESTONLY5678'].join('_');
const githubToken = ['gh', 'p_', 'TESTONLY0123456789abcd'].join('');
const awsKey = ['AK', 'IA', 'TESTONLY000000AB'].join('');
const jwt = ['eyJ', 'hbGciOiJIUzI1NiJ9', '.', 'eyJzdWIiOiJ0ZXN0In0', '.', 'signaturePart1'].join('');
const stored = { name: 'STRIPE_KEY', value: 'FAKE-STORED-VALUE-0001' };
const base64 = (text: string) => Buffer.from(text, 'utf8').toString('base64');

test('stored value is masked in raw and base64 form, and the marker names the secret, never the value', () => {
  const b64 = Buffer.from(stored.value, 'utf8').toString('base64');
  const text = `raw=${stored.value} encoded=${b64} again=${stored.value}`;
  const out = redactText(text, [stored]);
  assert.equal(out, 'raw=[REDACTED:STRIPE_KEY] encoded=[REDACTED:STRIPE_KEY] again=[REDACTED:STRIPE_KEY]');
  assert.equal(out.includes(stored.value), false);
  assert.equal(out.includes(b64), false);
});

test('a stored value inside a longer base64 payload is masked at every alignment, leaving at most two border characters', () => {
  const marker = '[REDACTED:STRIPE_KEY]';
  // Authorization: Basic base64(user:value) is the usual case. The bytes before the value decide its alignment.
  for (const prefix of ['', 'u', 'us', 'user:']) {
    for (const suffix of ['', ':', ':and-more']) {
      const where = `prefix ${JSON.stringify(prefix)}, suffix ${JSON.stringify(suffix)}`;
      const encoded = base64(`${prefix}${stored.value}${suffix}`);
      const pieces = redactText(encoded, [stored]).split(marker);
      assert.equal(pieces.length, 2, `masked once: ${where}`);
      const [head = '', tail = ''] = pieces;
      assert.ok(encoded.startsWith(head) && encoded.endsWith(tail), `the text around the marker is untouched: ${where}`);
      // A base64 character holds 6 bits. It reveals part of the value when those bits overlap the value's bytes.
      const firstBit = Buffer.byteLength(prefix) * 8;
      const endBit = firstBit + Buffer.byteLength(stored.value) * 8;
      const kept = [...Array.from(head, (_, index) => index), ...Array.from(tail, (_, index) => encoded.length - tail.length + index)];
      const revealing = kept.filter(index => index * 6 < endBit && index * 6 + 6 > firstBit);
      assert.ok(revealing.length <= 2, `${revealing.length} characters that carry the value stay readable: ${where}`);
      assert.deepEqual(findLeaks(`Authorization: Basic ${encoded}`, [stored]), ['STRIPE_KEY'], `reported by name: ${where}`);
    }
  }
});

test('embedded masking leaves unrelated base64 alone, and a value too short for a safe stretch gets no embedded form', () => {
  const unrelated = `Authorization: Basic ${base64('user:FAKE-UNRELATED-PASSWORD')}`;
  assert.equal(redactText(unrelated, [stored]), unrelated);
  assert.deepEqual(findLeaks(unrelated, [stored]), []);

  // The shortest value the vault accepts leaves exactly the minimum stretch at each alignment.
  const shortest = 'FAKE-678';
  assert.equal(Buffer.byteLength(shortest), MIN_SECRET_LENGTH);
  assert.equal(MIN_EMBEDDED_BASE64_LENGTH, 10);
  assert.deepEqual(valueVariants(shortest).map(variant => variant.length), [12, 10, 10, 10, 8]);

  // One byte less would leave 8 or 9 characters, below the minimum: no embedded form.
  const tooShort = 'FAKE-67';
  assert.deepEqual(valueVariants(tooShort), [base64(tooShort), tooShort]);
  const embedded = base64(`u${tooShort}:`);
  assert.equal(redactText(embedded, [{ name: 'SHORT', value: tooShort }]), embedded);
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

test('variants are the raw value, its base64 form and that form at the other alignments, longest first', () => {
  // 15 bytes, a multiple of 3: encoded alone or after 3, 6... bytes the value gives the same 20 characters.
  const aligned = 'FAKE-SECRET-XYZ';
  assert.deepEqual(valueVariants(aligned), [
    base64(aligned),
    // After 1 byte: 2 characters carry that byte and the last one carries whatever follows the value.
    base64(`u${aligned}`).slice(2, 21),
    // After 2 bytes: 3 characters carry them and the last one carries whatever follows the value.
    base64(`us${aligned}`).slice(3, 22),
    aligned,
  ]);

  // 16 bytes: the padded form only matches the value encoded alone, so the unpadded stretch is a variant of its own.
  const unaligned = 'FAKE-SECRET-WXYZ';
  assert.deepEqual(valueVariants(unaligned), [
    base64(unaligned),
    base64(unaligned).slice(0, 21),
    base64(`us${unaligned}`).slice(3, 24),
    base64(`u${unaligned}`).slice(2, 22),
    unaligned,
  ]);
});
