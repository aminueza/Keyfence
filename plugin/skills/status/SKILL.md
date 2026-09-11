---
description: Show whether the keyfence proxy is protecting this session and what it has caught recently.
disable-model-invocation: true
allowed-tools: Bash(keyfence doctor*), Bash(keyfence status*)
---

Run `keyfence doctor` and `keyfence status` with the Bash tool. Report, in a
few lines: whether the proxy is listening and this shell is routed through it,
how many secrets the vault holds, and the most recent detections. If doctor
reports a FAIL line, quote it and say what to run. Do not print secret values;
keyfence never shows them, and neither should you.
