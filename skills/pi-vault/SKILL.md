---
name: pi-vault
description: Use credentials without seeing them. Use when a task needs an API key, token or password (Stripe, GitHub, Slack, cloud, database) or when a secret may have entered the conversation. Covers vault_run (run a command with secrets injected as environment variables that only that command sees), vault_list (names and readiness, never values), the {{secret:NAME}} placeholder, and what the operator does to add a secret.
---

# pi-vault

Secrets never pass through you. The vault holds their values; you name them.

## Tools

- `vault_list`: the secret names, where each is kept, and whether it resolves. It never returns a value.
- `vault_run`: runs one shell command (bash syntax) with the named secrets as environment variables of that command only.
  - Write the secret where its value belongs as `{{secret:NAME}}`, inside double quotes when it is an argument. The shell receives `${NAME}`.
  - Or list the names in `secrets: ["NAME"]` and read `$NAME` yourself.
  - The output comes back masked: a value appears as `[REDACTED:NAME]`.

```
vault_run  command: curl -s -u "{{secret:STRIPE_KEY}}:" https://api.stripe.com/v1/balance
```

## Rules

- Never type, paste, print or write a secret value. A command or tool argument that contains a stored value or a live-token shape (`sk_live_`, `rk_live_`, `ghp_`, `xox*`, `AKIA`, JWT) is refused before it runs.
- A masked `[REDACTED:...]` in a result means a secret was present and hidden. Do not try to reconstruct it.
- If a result is refused, read the reason: it names the secret or the shape, never the value. Use `vault_list` to check the name.
- A secret that is `unavailable` cannot be used. Ask the operator to add or fix it; do not ask him for the value in chat.
- Adding a secret is the operator's job, in his own terminal (`npm run vault -- add NAME`). Never ask for a value in a tool argument or in the conversation.

## When a value has already leaked

If a secret appeared in a conversation, log or file, tell the operator, so he can rotate it. Redaction masks what Pi sees from now on; it cannot unsend what was already sent.
