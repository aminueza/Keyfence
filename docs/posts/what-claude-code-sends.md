# What Claude Code actually sends, seen from a proxy

*Draft. Numbers and paths below come from running Claude Code 2.1 through
keyfence in September 2026 on one machine. They describe what one setup
sent, not a specification.*

Coding agents work by putting things in front of a model: your prompt, the
files they read, the output of the commands they run. Everything the model
sees travels over HTTPS to the provider. Most people never look at that
traffic. I put a proxy in the middle to see what was in it, because I
wanted to know what happens when an agent reads a `.env` file.

## The setup

keyfence is a local mitmproxy-based proxy that scans requests to LLM
providers. In `audit` mode it changes nothing and only records what it
would have caught. Run Claude Code through it:

```bash
uv tool install keyfence
printf 'mode: audit\n' > ~/.keyfence/config.yaml
keyfence exec -- claude
```

Then read the audit log. Every line is one request that contained something
that looked like a secret, with the endpoint, the kind of secret and the
JSON field it sat in. Never the value.

## Three kinds of requests

Claude Code talks to `api.anthropic.com` on three paths.

**`/v1/messages`** is the conversation. Each turn re-sends the whole
transcript: system prompt, every user message, every tool call and every
tool result so far. When the agent reads a file with its `Read` tool, the
file's contents arrive here inside a `tool_result` block, under the JSON
key `content`. When it runs `cat .env` instead, the contents arrive the same
way. A 30-line `.env` is a 30-line string in a JSON body.

**`/v1/code/sessions/<id>/worker/events`** and
**`.../worker/internal-events`** are session event streams. In our runs
they carried the same tool output a second time, under keys such as
`content` and `stdout`. A secret that the agent read showed up in the
audit log once for the conversation and twice more for these streams, on
the same second.

**`/api/event_logging/v2/batch`** is telemetry. The bodies we saw were
batches of up to 800 base64-encoded JSON objects, 260 to 1,460 characters
each, several hundred kilobytes per request, sent every ten to fifteen
seconds while the session was idle. We did not decode them and make no
claim about their contents. They matter here for a different reason: a
naive secret detector flags every one of those strings, because random
base64 has exactly the statistical profile of a key. The first version of
keyfence reported 800 findings per telemetry request. That is worth
knowing if you build or evaluate a scanner for this traffic.

## What the file contents look like to the model

Here is the part that motivated the proxy. A `.env` with two lines,

```
GITHUB_TOKEN=ghp_…
DB_PASSWORD=…
```

read by the `Read` tool, reaches the model as a tool result. With keyfence
in `redact` mode the model receives:

```
GITHUB_TOKEN=[REDACTED:vault]
DB_PASSWORD=[REDACTED:vault]
```

and answers, when asked for the values, that they are masked. With no
proxy, the model receives the values. It does not need them to answer
"read .env"; it gets them anyway, because the tool returns the whole file.

To make this visible rather than argued, keyfence has a canary:
`keyfence canary .env` appends a fake variable to the file and registers
it. It is useless as a credential, so the only way it can appear in a
request is that a tool read the file and sent it. In our run the canary
showed up in the next `/v1/messages` request and in both event streams,
each entry naming the file it came from.

## Two things the model's own answers taught us

The first time Claude saw `[REDACTED:vault]` in a tool result, it explained
correctly that a protection layer had masked the values, and then advised
rotating the credentials because "the file had been tampered with". A
redaction the model does not understand looks like an attack. keyfence now
appends one sentence to the system prompt of any request it changed,
saying that the tokens are expected, not a compromise, and should be
written verbatim if needed. The advice to rotate stopped.

The second: the model repeated `GITHUB_TOKEN=[REDACTED]` in its answer, the
answer went back in the next request, and the detector flagged
`[REDACTED]` as a secret and redacted the redaction. Any scanner on this
path has to recognise its own output.

## What we would tell someone building on this

- The conversation body is the one that matters, and it is plain JSON:
  scanning it is cheap and precise. Ids, signatures and base64 fields need
  to be excluded by JSON key, not by pattern, or the false positives drown
  everything.
- The same content travels more than once. Count detections per file, not
  per request.
- Telemetry is large and random-looking. Decide explicitly whether to scan
  it.
- The model reacts to what you change. Tell it.

The proxy, the audit log format and the numbers above are reproducible
with keyfence; the corpus behind its benchmark includes request bodies
shaped like the ones described here.
