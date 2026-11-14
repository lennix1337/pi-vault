/**
 * Detection and masking of secrets in text. Pure functions: no I/O, no logging.
 *
 * A stored value is found in its raw form and in its base64 form, alone or
 * inside a larger base64 payload, because a command that encodes a credential
 * would otherwise carry it past the check.
 * Known token shapes are matched even when the value is not stored, so a live
 * key pasted by the model or printed by a file is still masked.
 */

export interface KnownSecret {
  readonly name: string;
  readonly value: string;
}

/** Values shorter than this cannot be masked safely (they would hide ordinary text), so they are never injected. */
export const MIN_SECRET_LENGTH = 8;

const SHAPES: readonly { readonly label: string; readonly pattern: RegExp }[] = [
  { label: 'stripe-live-key', pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{8,}/ },
  { label: 'stripe-webhook-secret', pattern: /\bwhsec_[A-Za-z0-9]{8,}/ },
  { label: 'github-token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/ },
  { label: 'slack-token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { label: 'aws-access-key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { label: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: 'private-key', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/ },
  { label: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
];

function globalPattern(pattern: RegExp): RegExp {
  return new RegExp(pattern.source, `${pattern.flags.replace('g', '')}g`);
}

/**
 * Shortest base64 stretch masked as a value inside a larger payload: what a value of MIN_SECRET_LENGTH bytes
 * leaves once its border characters are dropped. A shorter stretch would also match ordinary text.
 */
export const MIN_EMBEDDED_BASE64_LENGTH = 10;

/** The forms of a stored value that must never reach the model: raw, base64, and base64 inside a larger payload. */
export function valueVariants(value: string): string[] {
  const variants = [value, Buffer.from(value, 'utf8').toString('base64')];
  return [...new Set([...variants, ...embeddedBase64(value)])].sort((a, b) => b.length - a.length);
}

/**
 * What the value encodes to inside a larger base64 payload, such as `Authorization: Basic base64(user:value)`.
 * Base64 packs 3 bytes into 4 characters, so the bytes before the value put it at one of three alignments. A
 * character that also holds bits of a neighbouring byte changes with that neighbour, so it is left out: 0, 2 or 3
 * at the start, and the last one unless the value ends on a 3-byte boundary.
 */
function embeddedBase64(value: string): string[] {
  const bytes = Buffer.from(value, 'utf8');
  return [0, 1, 2]
    .map(lead => {
      const encoded = Buffer.concat([Buffer.alloc(lead), bytes]).toString('base64').replace(/=+$/, '');
      return encoded.slice(Math.ceil((lead * 8) / 6), (lead + bytes.length) % 3 === 0 ? undefined : -1);
    })
    .filter(stretch => stretch.length >= MIN_EMBEDDED_BASE64_LENGTH);
}

/** Labels of every stored secret name and token shape found in the text. Never returns the matched text. */
export function findLeaks(text: string, secrets: readonly KnownSecret[]): string[] {
  const found: string[] = [];
  for (const secret of secrets) {
    if (valueVariants(secret.value).some(variant => text.includes(variant))) found.push(secret.name);
  }
  for (const shape of SHAPES) {
    if (globalPattern(shape.pattern).test(text)) found.push(shape.label);
  }
  return [...new Set(found)];
}

/** Masks every stored value in each of its forms (see valueVariants) and every known token shape. Markers name the secret or shape, never its value. */
export function redactText(text: string, secrets: readonly KnownSecret[]): string {
  let out = text;
  const variants = secrets.flatMap(secret => valueVariants(secret.value).map(variant => ({ name: secret.name, variant })));
  variants.sort((a, b) => b.variant.length - a.variant.length);
  for (const { name, variant } of variants) out = out.split(variant).join(`[REDACTED:${name}]`);
  for (const shape of SHAPES) out = out.replace(globalPattern(shape.pattern), `[REDACTED:${shape.label}]`);
  return out;
}

/** Applies a string transform to every string inside a JSON-like value; objects and arrays are copied, other values pass through. */
export function mapStrings<T>(value: T, transform: (text: string) => string): T {
  if (typeof value === 'string') return transform(value) as T;
  if (Array.isArray(value)) return value.map(item => mapStrings(item, transform)) as T;
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) out[key] = mapStrings(item, transform);
    return out as T;
  }
  return value;
}
