# pi-vault

[![npm](https://img.shields.io/npm/v/@lennix1337/pi-vault)](https://www.npmjs.com/package/@lennix1337/pi-vault)
[![check](https://github.com/lennix1337/pi-vault/actions/workflows/check.yml/badge.svg)](https://github.com/lennix1337/pi-vault/actions/workflows/check.yml)
[![license](https://img.shields.io/npm/l/@lennix1337/pi-vault)](LICENSE)

Install: `pi install npm:@lennix1337/pi-vault`

Use credentials without the model seeing them. The vault keeps secret values where Windows protects them, and gives the model only their names. A command that needs a secret receives it in its environment for that one run; the output comes back with every occurrence of the value masked.

Status: in daily use in the author's Pi (loaded from a local checkout); published on npm as `@lennix1337/pi-vault`. Built after a Stripe live key reached the model's context.

## What the model gets

| Tool | Does |
|---|---|
| `vault_list` | Lists secret names, where each is kept and whether it resolves. Never returns a value. |
| `vault_run` | Runs one shell command with named secrets injected as environment variables of that command. `{{secret:NAME}}` becomes `${NAME}`. The output is masked before it is returned. |

Hooks, for every Pi session that loads the package:

- `tool_call`: refuses any tool call whose arguments contain a stored value (raw or base64) or a token shape. Bash and PowerShell commands lose the environment variables that carry vault values, so the model's own commands cannot print them.
- `tool_result`: masks stored values and token shapes in the text and details of every tool result, including `read` and bash output.

Masked token shapes: `sk_live_`, `rk_live_`, `whsec_`, GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), Slack `xox*`, AWS `AKIA`/`ASIA` keys, Google `AIza` keys, JWTs, and PEM private key blocks.

## Where values live

`vault.json` (default `%USERPROFILE%\.pi-vault\vault.json`, or `PI_VAULT_DIR`) maps each secret name to a reference. It never holds a plaintext value.

| Source | Reference | Value kept in |
|---|---|---|
| `dpapi` (Windows) | hex blob | encrypted by DPAPI for the current Windows user |
| `credman` (Windows) | Credential Manager target `pi-vault:NAME` | Windows Credential Manager, generic credential |
| `env` (any OS) | name of an environment variable of the Pi process | that variable |

Values are decrypted in memory when Pi starts and again when `vault.json` changes on disk. Nothing writes them anywhere else.

## Operator: add a secret

Run this in your own terminal, not in a Pi session. The model cannot run it: it needs an interactive terminal and reads the value with no echo.

```
cd C:\projetos\pi-vault
npm install                       # once
npm run vault -- add STRIPE_KEY                       # Windows: DPAPI (default)
npm run vault -- add GITHUB_TOKEN --source credman    # Windows: Credential Manager
npm run vault -- link STRIPE_LEGACY --env STRIPE_LEGACY_KEY   # value stays in an environment variable
npm run vault -- check            # shows ready or unavailable, never values
npm run vault -- list             # names and sources
npm run vault -- remove NAME      # forgets NAME (deletes a Credential Manager entry)
```

- The value is typed at a hidden prompt. It is never accepted from arguments, pipes, files or the model. The value must be at least 8 characters.
- `add` refuses an existing name unless you pass `--replace`.
- A Credential Manager value is limited to 2048 bytes.
- Rotate a key at its provider after any exposure, and then run `add ... --replace`.

## The model's view of a run

```
vault_run  command: curl -s -u "{{secret:STRIPE_KEY}}:" https://api.stripe.com/v1/balance
result     {"status":"ok","exitCode":0,"injected":["STRIPE_KEY"],"stdout":"...[REDACTED:STRIPE_KEY]...", ...}
```

A command that contains a value, or a token shape, is refused with the name of what was found, never the value. Output is masked in full before it is cut to the display window.

## Design notes

- Values are passed to the child only through its environment. Other vault values are removed from the child environment, so a command sees only the secrets it was granted.
- Windows decryption runs in one Windows PowerShell process per start or change. The script exchanges values as base64, so no console code page can corrupt a secret, and no value appears on a command line. DPAPI uses `System.Security.Cryptography.ProtectedData`, not the SecureString cmdlets (those fail to auto-load on some systems).
- Shell: the same resolution as Pi's bash tool (`getShellConfig` from `@earendil-works/pi-coding-agent`).
- A value shorter than 8 characters is never injected: masking it would hide ordinary text.
- If `vault.json` cannot be read, `vault_run` refuses to run and the shape-based masking still applies.

## Risks and limits

- **The command decides where a secret goes.** The vault keeps a value out of the model's context, not out of the command. A command the model writes can send `$STRIPE_KEY` to any host. Gate `vault_run` with an approval (OptChat effect approvals) and keep it out of unattended runs.
- **Masking is by value and by shape.** Encodings beyond raw and base64 (hex, URL encoding, a value split across lines, reversed text) are not masked. A new token format is not masked until its shape is added.
- **Environment-sourced values** exist in the Pi process environment. The bash and PowerShell prefixes remove them from the model's commands, but a process started by Pi itself (an extension, a subagent) still inherits them.
- **Same-user malware can decrypt DPAPI and read Credential Manager.** Both protect against other Windows accounts and offline copies of `vault.json`, not against code running as you.
- **Plaintext is in memory** in the Pi process and in the child that was granted it.
- A tool call refused by the `tool_call` hook does not run. Whether Pi keeps a refused call's arguments in the session history was not verified. A value that reached Pi before this package was loaded is not removed from history.

## Tests

`npm run verify` (TypeScript, then `npm test`); `npm run mutations` removes each of eight guards (base64 and stdout/stderr masking, placeholder grant, unknown name, carrier scrub, literal refusal, value-free listing) in a disposable copy and requires a test to fail. The Windows tests use real DPAPI and a temporary Credential Manager entry with a fake value, deleted afterwards; they are skipped elsewhere. Injection, redaction, refusal, timeout, abort and the CLI run against the real shell.

## Install

`pi install npm:@lennix1337/pi-vault`, `pi install git:github.com/lennix1337/pi-vault`, or add a checkout's path to `packages` in `~/.pi/agent/settings.json`, then reload Pi. A fresh session discovers the packaged `pi-vault` skill. A `v*` tag runs `.github/workflows/release.yml` (npm publish with provenance through trusted publishing).
