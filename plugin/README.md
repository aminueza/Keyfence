# keyfence plugin for Claude Code

Two layers against secret leakage:

- A `PreToolUse` hook that refuses to read or grep `.env` files, private
  keys, `.netrc`, `.npmrc`, `.aws/credentials`, `.docker/config.json`,
  `.ssh` and similar, refuses shell commands that mention them, and refuses
  commands that print secrets: `env`, `printenv`, `export -p`, `set`,
  `aws secretsmanager get-secret-value`, `op read`, `vault kv get`,
  `doppler secrets`, `kubectl get secret`, `gcloud secrets versions access`,
  `az keyvault secret show`, `heroku config`. The hook is a self-contained
  Python 3 file inside the plugin, so it works even before keyfence is
  installed.
- Skills: `/keyfence:status` shows what the proxy is protecting and
  catching; `/keyfence:setup` walks through installing and wiring the proxy.

The skills call the `keyfence` command, so for the proxy layer install it:

```bash
uv tool install keyfence      # or: pip install keyfence
```

Then, inside Claude Code:

```
/plugin marketplace add aminueza/keyfence
/plugin install keyfence@keyfence
```

For the proxy layer, start Claude Code with `keyfence exec -- claude`. See
the [keyfence documentation](https://github.com/aminueza/keyfence#readme).
