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
- **Streams ending mid-placeholder.** If a streamed response ends in the
  middle of a placeholder, the last characters are passed through as they
  are.
- **Model behaviour.** keyfence controls what the model receives, not what
  it says. The system prompt notice reduces false alarms about redaction,
  but the model can still misread other parts of its context.

## Other measures

keyfence is the last line. It works best together with:

- A hook in your agent that denies reading `.env`, `*.pem` and
  `**/credentials*`. For Claude Code, `keyfence install-hooks claude-code`
  installs one.
- Secrets kept in a password manager or vault and passed as environment
  variables only to the process that needs them, where `keyfence exec`
  protects them.
- Git hooks such as gitleaks or trufflehog for the commit path.
