# PasteSafe

[![CI](https://github.com/ihsieh31/pastesafe/actions/workflows/ci.yml/badge.svg)](https://github.com/ihsieh31/pastesafe/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/pastesafe.svg)](https://www.npmjs.com/package/pastesafe)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Scan anything before you paste it into an LLM.**

You are one `Ctrl+V` away from shipping a production key to a third party. PasteSafe
reads whatever is on your clipboard, your terminal, a file, a diff, or stdin, and tells
you what would leak — then hands you back a version with every secret replaced.

```bash
$ pb paste "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"

  CRITICAL aws.access-key-id 1:19
           AWS access key ID
           AWS_ACCESS_KEY_ID=«aws.access-key-id#fba7f486»

  1 secret found. PasteSafe did not send anything anywhere.
```

That example key is the one from AWS's own documentation, and PasteSafe flags it on
purpose — a real secret and a documentation sample are indistinguishable by pattern,
which is exactly why the scan is worth running. Silence known-good lines with
`// pastesafe:allow:aws.access-key-id`.

- **Zero dependencies.** No telemetry, no network calls, nothing phoned home.
- **Redaction is one-way.** There is no function in this package that can turn a
  placeholder back into a secret, so a redaction bug cannot become a second leak.
- **False positives are designed out.** Credit cards must pass Luhn, Taiwan national
  IDs must pass their mod-10 checksum, JWTs must have a decodable header, and
  placeholders like `${API_KEY}` or `changeme` are never reported.

## Install

```bash
npm install -g pastesafe
```

## Use it

```bash
pastesafe                    # read stdin (pipe anything in)
pastesafe config.env         # scan a file
pastesafe -t "some text"     # scan a string — this is the clipboard path
pastesafe < bad-dump.log     # scan a big log
pastesafe --redact < leak.ts # print the file with every secret replaced
```

### In CI

```bash
pastesafe --sarif --fail-on high . > pastesafe.sarif
```

Uploads to GitHub code scanning as-is. Or block commits outright:

```bash
pastesafe --install-hook
```

That drops in a `pre-commit` hook that scans your staged diff, so a key never
reaches `main` in the first place. Bypass with `git commit --no-verify` when you
know it is fine.

## Output modes

| Flag | What you get |
| --- | --- |
| *(default)* | Human-readable report, colourised, secrets already removed |
| `--redact` | The input itself, rewritten with every secret replaced |
| `--json` | Findings array, for piping into your own tooling |
| `--sarif` | SARIF 2.1.0, for GitHub code scanning |

## Narrowing the noise

```bash
pastesafe --verified .                  # only checksum-backed findings (near-zero FPs)
pastesafe --only github.pat,openai.api-key .
pastesafe --skip pii.email .            # don't care about emails
pastesafe --no-entropy .                # drop the catch-all rule, faster
pastesafe --fail-on critical .          # only fail CI on the worst stuff
```

Per-line opt-out when a finding is a false positive:

```ts
const DEMO_KEY = "sk-ant-...";   // pastesafe:allow:openai.api-key
const DEBUG = true;              // pastesafe:allow
```

## What it catches

Secrets — AWS, GCP, Azure, OpenAI, Anthropic, Hugging Face, Replicate, Perplexity,
GitHub (classic + fine-grained), GitLab, npm, PyPI, Stripe, Shopify, Square,
Braintree, Slack, Discord, Telegram, Twilio, SendGrid, Mailgun, Postmark, PEM private
keys, JWTs, bearer/basic auth headers, database connection strings, tokens in URL query
strings, and any credential-shaped assignment.

PII — payment card numbers (Luhn-validated), Taiwan national IDs (checksum-validated),
US SSNs, email addresses.

Plus a Shannon-entropy catch-all for secrets from services nobody has a rule for yet.

```js
import { scan, redact } from 'pastesafe';

const { findings, summary } = scan(pastedText);
if (summary.total > 0) {
  console.log(redact(pastedText, findings).text);
}
```

## How the fingerprints work

Each secret gets a stable 8-character hash derived from `sha256(rule_id + secret)`.
The same key appearing five times in a diff collapses to one fingerprint, so you can
see "these four are the same leaked key" without the key ever being displayed. The
fingerprint is safe to put in a public bug report; the secret is not in it.

## Design notes

Overlapping matches collapse — the most specific rule always wins. A high-entropy
token like `AWS_ACCESS_KEY_ID=AKIA...` stands down when a precise rule matches inside
it, so redaction leaves `AWS_ACCESS_KEY_ID=` readable.

Findings objects never carry the raw secret, which means `--json` and `--sarif` output
can be attached to a public issue without a second incident.

## Development

```bash
npm test
```

MIT
