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
  `HTTPS_PROXY` or the system proxy bypasses keyfence. Transparent capture
  by process name is planned.
- **Local models.** Ollama and similar do not go through the proxy. Their
  traffic also does not leave the machine.
- **Streams ending mid-placeholder.** If a streamed response ends in the
  middle of a placeholder, the last characters are passed through as they
  are.
- **Model behaviour.** keyfence controls what the model receives, not what
  it says. The system prompt notice reduces false alarms about redaction,
  but the model can still misread other parts of its context.

## Other measures

keyfence is the last line. It works best together with:

- Permission rules or hooks in your agent that deny reading `.env`,
  `*.pem` and `**/credentials*`.
- Secrets kept in a password manager or vault and passed as environment
  variables only to the process that needs them, where `keyfence exec`
  protects them.
- Git hooks such as gitleaks or trufflehog for the commit path.
