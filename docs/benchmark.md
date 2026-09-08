# Benchmark

Measured on 2026-09-08 with keyfence 0.3.0 and gitleaks 8.30.1, on a
synthetic corpus of 411 positive and 288 negative samples (709 KB).
Reproduce with:

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
| code | 170 | chunks of keyfence's own source and of the Python standard library |
| claude-code-body | 40 | request bodies shaped like Claude Code's, with tool ids, thinking signatures, base64 images and hashes in tool output |
| telemetry | 20 | batches of base64-encoded JSON events |
| logs | 20 | log lines with UUIDs, trace ids, commit hashes and IPs |
| lockfile | 20 | `package-lock.json` entries with `sha512-` integrity hashes and `go.sum` lines |
| prose | 18 | chunks of this project's documentation |

A positive counts as detected when a finding equals the planted secret or
overlaps it. A negative counts as a false positive when it has any finding.

## Results

Columns are keyfence with only the built-in rules, with the bundled gitleaks
rules added, with the entropy check added (the default configuration), the
default with the two formatless secrets registered in the vault, and the
gitleaks binary run over the same samples as files.

| | builtin patterns | + gitleaks rules | + entropy (default) | default + vault | gitleaks binary |
|---|---|---|---|---|---|
| recall on formatted secrets | 100% | 100% | 100% | 100% | 93% |
| precision (per sample) | 100% | 100% | 100% | 100% | 100% |
| negatives with a finding | 1 / 288 | 1 / 288 | 1 / 288 | 1 / 288 | 0 / 288 |
| total false findings | 2 | 2 | 2 | 2 | 0 |
| time | 0.3s | 0.5s | 0.6s | 0.8s | 0.0s |

Recall by format:

| format | builtin patterns | + gitleaks rules | + entropy (default) | default + vault | gitleaks binary |
|---|---|---|---|---|---|
| anthropic | 100% | 100% | 100% | 100% | 86% |
| aws-access-key-id | 100% | 100% | 100% | 100% | 100% |
| doppler | 100% | 100% | 100% | 100% | 100% |
| github-fine-grained | 100% | 100% | 100% | 100% | 100% |
| github-pat | 100% | 100% | 100% | 100% | 100% |
| gitlab-pat | 100% | 100% | 100% | 100% | 100% |
| google-api-key | 100% | 100% | 100% | 100% | 86% |
| huggingface | 100% | 100% | 100% | 100% | 86% |
| jwt | 100% | 100% | 100% | 100% | 86% |
| npm | 100% | 100% | 100% | 100% | 86% |
| openai | 100% | 100% | 100% | 100% | 86% |
| passphrase | 57% | 71% | 71% | 100% | 38% |
| pem-private-key | 100% | 100% | 100% | 100% | 100% |
| pypi | 100% | 100% | 100% | 100% | 100% |
| random-password | 52% | 52% | 52% | 100% | 10% |
| sendgrid | 100% | 100% | 100% | 100% | 86% |
| slack-bot-token | 100% | 100% | 100% | 100% | 100% |
| slack-webhook | 100% | 100% | 100% | 100% | 100% |
| stripe-live | 100% | 100% | 100% | 100% | 86% |
| twilio | 100% | 100% | 100% | 100% | 100% |

False positive rate by negative category (share of samples with at least one
finding):

| category | samples | builtin patterns | + gitleaks rules | + entropy (default) | default + vault | gitleaks binary |
|---|---|---|---|---|---|---|
| claude-code-body | 40 | 0% | 0% | 0% | 0% | 0% |
| code | 170 | 0% | 0% | 0% | 0% | 0% |
| lockfile | 20 | 0% | 0% | 0% | 0% | 0% |
| logs | 20 | 0% | 0% | 0% | 0% | 0% |
| prose | 18 | 6% | 6% | 6% | 6% | 0% |
| telemetry | 20 | 0% | 0% | 0% | 0% | 0% |

## Reading the numbers

- **Formatless secrets are the point of the vault.** A random password is
  caught about half the time by patterns (only when it sits after
  `password=` or a similar name) and never reliably by anything else. With
  the value registered through `keyfence import`, recall is 100%.
- **The 86% column for gitleaks is one context.** gitleaks catches every
  format in `.env`, YAML, code, curl, JSON and tool results, and misses the
  prose context (`... it is <secret>, please ignore it.`) because most of
  its rules require the secret to be followed by whitespace, a quote or the
  end of the line, not a comma. keyfence's built-in rules use word
  boundaries.
- **The one keyfence false positive is real by design.** The flagged prose
  sample is the setup guide, which contains an example `.env` with a fake
  token and password.
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
  detection only, on the same text, because keyfence bundles its rules.
- Other LLM proxies are not included. LLM-Redactor uses the gitleaks rules
  as well; og-local uses an ML model with a different trade-off. Running
  them needs their binaries, and the runner in `bench/run.py` accepts new
  detectors as plain functions if you want to add them.
