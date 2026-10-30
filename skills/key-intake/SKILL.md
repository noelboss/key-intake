---
name: key-intake
description: Use when you need an API key, token or password from the human (new service, rotated credential, missing keychain entry) — opens a native macOS window that stores it in the login keychain so the secret never appears in chat.
---

# key-intake

Takes a secret from the human straight into the macOS login keychain. You never see the value; you only get `stored NAME`.

## Rules

- Never ask the human to paste a secret into chat, a file, or a command line.
- Never print, log, echo or write a secret you read back.
- First check whether it already exists: `security find-generic-password -s NAME >/dev/null 2>&1` (no `-w`, no output).

## Ask for a key

Run in the background (the window waits for the human), with the exact page where the key is created and numbered-step content:

```bash
key-intake NAME="Label on the page" [NAME2="Label2" …] \
  --url "https://exact.page/where/the/key/is/created" \
  --steps "Token type | Permissions: … | Scope: which resources | Lifetime | What to copy"
```

- `NAME`: letter/digit first, then letters, digits, `_ . -`, max 128. It becomes the keychain service name. Pick a clear, project-scoped name.
- `="label"` (optional, max 200 chars): the value on the page that belongs in this row. Names from the same page share one group; one call can hold several groups, each ending with its own `--url` and `--steps`.
- `--url`: https only. `--steps`: separated by `|`, max 12, complete (token type, permissions, scope, lifetime, what to copy). The window numbers them.
- Tell the human in chat what you are asking for and why, but never the value.

## Read it back

Inline, at the moment of use, never into a variable you print:

```bash
curl -H "Authorization: Bearer $(security find-generic-password -s NAME -w)" https://api.example.com/
```

## Result

One line per name on stdout: `stored NAME` · `skipped NAME` · `failed NAME <reason>`.

| Exit | Meaning | You do |
|---|---|---|
| 0 | at least one stored | proceed; check each line |
| 1 | cancelled or nothing stored | do not retry on your own; tell the human the key is still missing and ask how to continue |
| 2 | error (bad args, build failure, `failed` line) | fix the call from the message; `failed … keychain locked` → ask the human to unlock the keychain |

There is no timeout: the window stays until the human saves or cancels. An existing name is only overwritten if the human ticks "replace".

Needs macOS with a graphical session and `swiftc` (Xcode Command Line Tools). `key-intake --help` shows the full usage.
