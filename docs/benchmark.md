# Benchmark

Measured on 2026-09-24 with keyfence 0.8.0.dev0, gitleaks 8.30.1 and
Python 3.13, on a synthetic corpus of 411 positive and 311 negative samples
(871 KB as sent). Reproduce with:

```bash
python bench/run.py
```

## Corpus

Nothing in the corpus is a real secret, and none of it is committed: the
generator uses a fixed seed. Positives are fake secrets in 20 formats, each
built to the real format (AWS keys use the base32 alphabet, Anthropic keys
have 93 characters and end in `AA`, OpenAI keys carry the `T3BlbkFJ` marker,
and so on), embedded in seven contexts: a `.env` line, a chat request body,
prose, source code, YAML, a curl command, and a Claude Code tool result with
line numbers. Two formats are formatless on purpose: a random 20-character
password and a passphrase made of dictionary words.

Negatives are content that should never be flagged:

| category | samples | what it is |
|---|---|---|
| code | 179 | chunks of keyfence's own source and of the Python standard library |
| claude-code-body | 40 | request bodies shaped like Claude Code's, with tool ids, thinking signatures, base64 images and hashes in tool output |
| prose | 32 | chunks of this project's documentation, except this page |
| telemetry | 20 | batches of base64-encoded JSON events |
| logs | 20 | log lines with UUIDs, trace ids, commit hashes and IPs |
| lockfile | 20 | `package-lock.json` entries with `sha512-` integrity hashes and `go.sum` lines |

The code samples include modules of the standard library of the Python that
runs the benchmark, so their count depends on the Python version: 179 on
3.13, 205 on 3.14. The output names the version it ran on. This page is left
out of the prose samples: it holds the results, so regenerating it would
change the corpus it describes.

## As sent

The proxy never sees a sample as plain text. Every secret reaches it inside
a JSON request body, where a quote is `\"`, a newline is `\n` and, for
clients that serialise with `ensure_ascii`, a non-ASCII letter is `\uXXXX`.
So every sample is measured the way it is sent: the chat body and tool
result contexts, the Claude Code bodies and the telemetry batches are
request bodies already and are used as they are; everything else is
wrapped as the content of a `tool_result` in a messages body, a third of
them with `ensure_ascii`. The headline tables below are computed on those
bodies. `bench/run.py` also measures the raw text, and the context table
shows the raw recall in parentheses where it differs.

A positive counts as detected when a finding equals the planted secret or
overlaps it, in its plain or JSON-escaped form. A negative counts as a false
positive when it has any finding.

## Results

Columns are keyfence with only the built-in rules, with the bundled gitleaks
rules added, with the entropy check added (the default configuration), the
default with the two formatless secrets registered in the vault, and the
gitleaks binary run over the same bodies as files.

| | builtin patterns | + gitleaks rules | + entropy (default) | default + vault | gitleaks binary |
|---|---|---|---|---|---|
| recall on formatted secrets | 100% | 100% | 100% | 100% | 81% |
| precision (per sample) | 99% | 99% | 99% | 99% | 100% |
| negatives with a finding | 2 / 311 | 2 / 311 | 2 / 311 | 2 / 311 | 0 / 311 |
| total false findings | 5 | 5 | 5 | 5 | 0 |
| time | 0.3s | 0.5s | 0.5s | 0.6s | 0.0s |

Recall by format:

| format | builtin patterns | + gitleaks rules | + entropy (default) | default + vault | gitleaks binary |
|---|---|---|---|---|---|
| anthropic | 100% | 100% | 100% | 100% | 57% |
| aws-access-key-id | 100% | 100% | 100% | 100% | 100% |
| doppler | 100% | 100% | 100% | 100% | 100% |
| github-fine-grained | 100% | 100% | 100% | 100% | 100% |
| github-pat | 100% | 100% | 100% | 100% | 100% |
| gitlab-pat | 100% | 100% | 100% | 100% | 100% |
| google-api-key | 100% | 100% | 100% | 100% | 57% |
| huggingface | 100% | 100% | 100% | 100% | 57% |
| jwt | 100% | 100% | 100% | 100% | 62% |
| npm | 100% | 100% | 100% | 100% | 57% |
| openai | 100% | 100% | 100% | 100% | 57% |
| passphrase | 57% | 71% | 71% | 100% | 19% |
| pem-private-key | 100% | 100% | 100% | 100% | 100% |
| pypi | 100% | 100% | 100% | 100% | 100% |
| random-password | 52% | 52% | 52% | 100% | 5% |
| sendgrid | 100% | 100% | 100% | 100% | 57% |
| slack-bot-token | 100% | 100% | 100% | 100% | 100% |
| slack-webhook | 100% | 100% | 100% | 100% | 100% |
| stripe-live | 100% | 100% | 100% | 100% | 57% |
| twilio | 100% | 100% | 100% | 100% | 100% |

Recall by context, as sent (raw text in parentheses where it differs):

| context | builtin patterns | + gitleaks rules | + entropy (default) | default + vault | gitleaks binary |
|---|---|---|---|---|---|
| code | 100% | 100% | 100% | 100% | 52% (raw 93%) |
| curl | 89% | 95% | 95% | 100% | 47% (raw 95%) |
| env-line | 98% | 98% | 98% | 100% | 91% |
| json-message | 90% | 90% | 90% | 100% | 90% |
| prose | 90% | 90% | 90% | 100% | 50% |
| tool-result | 100% | 100% | 100% | 100% | 92% |
| yaml | 100% | 100% | 100% | 100% | 95% |

False positive rate by negative category (share of samples with at least one
finding):

| category | samples | builtin patterns | + gitleaks rules | + entropy (default) | default + vault | gitleaks binary |
|---|---|---|---|---|---|---|
| claude-code-body | 40 | 0% | 0% | 0% | 0% | 0% |
| code | 179 | 1% | 1% | 1% | 1% | 0% |
| lockfile | 20 | 0% | 0% | 0% | 0% | 0% |
| logs | 20 | 0% | 0% | 0% | 0% | 0% |
| prose | 32 | 3% | 3% | 3% | 3% | 0% |
| telemetry | 20 | 0% | 0% | 0% | 0% | 0% |


## Reading the numbers

- **Formatless secrets are the point of the vault.** Patterns catch a
  random password only when it sits unquoted after `password=` or a
  similar name, quoted or not: 52% as sent. With the value registered through
  `keyfence import`, recall is 100%.
- **A quoted value reads the same in a body as in raw text.** Detection
  runs on the decoded body, so `api_key="..."` in the `code` context is
  found through the `\"` the client sends: that row is 100%, and
  `random-password` and `passphrase` match their raw-text recall. The one
  false finding that comes with it is keyfence's own `DEMO_PASSWORD =
  "correct-horse-battery-staple-2026"`, counted as a negative because the
  corpus reads this project's source.
- **gitleaks loses more in a request body.** Most of its rules require the
  secret to be followed by whitespace, a quote or the end of the line. In a
  JSON body the secret is followed by an escape such as `\"` or `\n`,
  whose backslash is none of those, so its recall drops from 93% to 52% in
  the code context and from 95% to 47% in curl. Prose is at 50% either way,
  because there a comma follows the secret.
- **The keyfence false positives are real by design.** One prose sample is
  the setup guide, which contains an example `.env` with a fake token and
  password. One code sample is `keyfence/demo.py`, whose fake request
  assigns `{DEMO_TOKEN}`-style template fields to secret names.
- **Entropy adds nothing on this corpus** and costs a little time. It stays
  on by default because it is the only check that catches an unknown
  format that was not registered in the vault; the exclusions documented in
  [detection.md](detection.md) are what keep it at zero false positives on
  Claude Code bodies, lockfiles, logs and telemetry.

## What this does not show

- The corpus is synthetic. Real traffic has more variety, and two of the
  entropy exclusions were added after false positives showed up in real
  Claude Code sessions, which is also how this corpus got its
  `claude-code-body` and `telemetry` categories.
- gitleaks is a repository scanner, not a proxy. It is compared here on
  detection only, on the same bodies, because keyfence bundles its rules.
- Other LLM proxies are not included. LLM-Redactor uses the gitleaks rules
  as well; og-local uses an ML model with a different trade-off. Running
  them needs their binaries, and the runner in `bench/run.py` accepts new
  detectors as plain functions if you want to add them.
