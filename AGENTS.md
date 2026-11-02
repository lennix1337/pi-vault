# pi-vault

Secrets never enter the model's context. Values live in Windows DPAPI or Credential Manager (or an environment variable of the Pi process); the model names them with `{{secret:NAME}}`. Read README.md for the design and the operator procedure.

Rules for changes:
- Never log, print, persist or return a value. Errors name secrets and reason codes only.
- Values reach the child process through its environment, never through its command line or the model's text.
- Every guard (refusal of literal secrets, redaction, scrub prefix, placeholder grant) has a test that fails without it.
- Adding a secret stays an interactive operator action. Do not add a tool argument that accepts a value.
- Tests use fake values built at run time (`['sk', 'live', ...].join('_')`), so no token-shaped literal sits in the repository.
- Runtime artifacts (vault files, temporary test directories) stay outside version control.
