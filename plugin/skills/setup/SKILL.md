---
description: Set up keyfence so secrets never reach the model, and explain how to run Claude Code through it.
disable-model-invocation: true
allowed-tools: Bash(keyfence *), Bash(which *), Bash(uv *), Bash(pip *)
---

Help the user get keyfence running. Steps, each with the Bash tool:

1. Check that the `keyfence` command exists (`which keyfence`). If not, tell
   the user to install it with `uv tool install keyfence` (or
   `pip install keyfence`) and stop.
2. Run `keyfence import` in the project directory so the user's own secrets
   are registered as hashes. Report how many were added, never the values.
3. Run `keyfence doctor` and summarise the result.
4. Explain that this plugin's hook already stops Claude Code from reading
   `.env` files, private keys and credential stores, and that the proxy is
   the second layer: the user starts Claude Code with
   `keyfence exec -- claude` so every request is scanned before it leaves the
   machine.

Keep it short. Never display secret values.
