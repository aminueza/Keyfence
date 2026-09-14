# Limitations

The target is accidental leakage, which is the overwhelming majority of
real incidents. Out of scope:

- **Certificate pinning.** Apps that pin the server certificate refuse the
  proxy. They fail instead of leaking, but they do not work through
  keyfence.
- **Obfuscation.** Secrets that are base64 encoded, split into pieces or
  encrypted are not detected. A program that hides secrets on purpose is
  outside the threat model.
- **Programs that ignore proxies.** Anything that does not honour
  `HTTPS_PROXY` or the system proxy bypasses keyfence unless you use
  `--local`, which needs mitmproxy's redirector approved in the operating
  system and works on macOS and Windows only.
- **Local models.** Ollama and similar do not go through the proxy. Their
  traffic also does not leave the machine.
- **Only the request body is scanned.** Headers and the URL query string
  are passed through untouched, in every mode, and the audit log records
  the path without its query. This is deliberate: the provider's own key
  travels in `Authorization` or, for Gemini, in `?key=`, and redacting it
  would break authentication. A secret you put in a query string yourself
  is not caught.
- **The agent hook cannot see what a search returns.** It refuses a grep
  aimed at a secret file, but a grep for `API_KEY` over the whole
  project with content output still returns the matching line of `.env`.
  A `PreToolUse` hook sees the tool's arguments, not its output. The proxy
  is the layer that catches that value on its way out. The hook also does
  not try to recognise `python -c 'print(os.environ)'` and similar
  one-liners; that is an arms race, and again the proxy covers the value
  itself once it is in the vault.
- **Streams ending mid-placeholder.** If a streamed response ends in the
  middle of a placeholder, the last characters are passed through as they
  are.
- **Model behaviour.** keyfence controls what the model receives, not what
  it says. The system prompt notice reduces false alarms about redaction,
  but the model can still misread other parts of its context.

## Other measures

keyfence is the last line. It works best together with:

- A hook in your agent that denies reading `.env`, `*.pem` and
  `**/credentials*`. `keyfence install-hooks claude-code` and
  `keyfence install-hooks pi` install one. Other agents need their own;
  `keyfence hook` takes `{"tool_name": ..., "tool_input": ...}` on stdin
  and exits 2 with the reason on stderr when a call must be refused.
- Secrets kept in a password manager or vault and passed as environment
  variables only to the process that needs them, where `keyfence exec`
  protects them.
- Git hooks such as gitleaks or trufflehog for the commit path.
