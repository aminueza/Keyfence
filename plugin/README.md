# keyfence plugin for Claude Code

Two layers against secret leakage:

- A `PreToolUse` hook that refuses to read `.env` files, private keys,
  `.netrc`, `.npmrc`, `.aws/credentials`, `.docker/config.json`, `.ssh`
  and similar, and refuses shell commands that mention them.
- Skills: `/keyfence:status` shows what the proxy is protecting and
  catching; `/keyfence:setup` walks through installing and wiring the proxy.

The hook and the skills call the `keyfence` command, so install it first:

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
