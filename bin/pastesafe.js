#!/usr/bin/env node
import { readFileSync, readdirSync, statSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import process from 'node:process';

import { scan } from '../src/scanner.js';
import { redact, formatText } from '../src/redact.js';
import { toSarif } from '../src/sarif.js';
import { RULES_BY_ID } from '../src/detectors.js';

const RANK = { critical: 4, high: 3, medium: 2, low: 1 };

const HELP = `
pastesafe — scan anything before you paste it into an LLM

USAGE
  pastesafe                        read from stdin
  pastesafe <file>...              scan files
  pastesafe -t "some text"         scan a string
  pastesafe -                      scan stdin explicitly

OUTPUT
  --json                    machine-readable findings
  --sarif                   SARIF 2.1.0 (GitHub code scanning compatible)
  --redact                  print the input with every secret replaced
  --mode <f|m>              redaction style: fingerprint (default) | full
  --no-entropy              skip the generic high-entropy rule (faster, fewer FPs)

SELECTION
  --only <id,id>            run only these rules
  --skip <id,id>            ignore these rules
  --verified                only report checksum-verified findings
  --fail-on <level>         exit non-zero at or above: critical|high|medium|low|none
                           (default: high, so CI fails on likely-real leaks)

  --install-hook            add a git pre-commit hook that scans staged diffs
  -h, --help                this text

NOTES
  Redaction is one-way on purpose: PasteSafe never has a way to reverse a
  placeholder, so a redaction mistake cannot leak the original.

  Rules can be silenced per line with a trailing comment:
    KEY = "sk-ant-..."        # pastesafe:allow:openai.api-key
    DEBUG = true              // pastesafe:allow
`;

function parseArgs(argv) {
  const opts = {
    files: [],
    text: null,
    json: false,
    sarif: false,
    redact: false,
    mode: 'fingerprint',
    entropy: true,
    only: null,
    skip: [],
    verified: false,
    failOn: 'high',
    installHook: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case '-h': case '--help': opts.help = true; break;
      case '--json': opts.json = true; break;
      case '--sarif': opts.sarif = true; break;
      case '--redact': opts.redact = true; break;
      case '--no-entropy': opts.entropy = false; break;
      case '--verified': opts.verified = true; break;
      case '--install-hook': opts.installHook = true; break;
      case '-t': case '--text': opts.text = next(); break;
      case '--mode': opts.mode = next(); break;
      case '--only': opts.only = (next() ?? '').split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--skip': opts.skip = (next() ?? '').split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--fail-on': opts.failOn = next(); break;
      case '-': opts.files.push('-'); break;
      default:
        if (a.startsWith('-')) {
          process.stderr.write(`pastesafe: unknown flag ${a}\n`);
          process.exit(2);
        }
        opts.files.push(a);
    }
  }
  return opts;
}

function readStdin() {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

/** Directories that never contain source worth scanning, and would be huge. */
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt',
  'vendor', '.venv', 'venv', '__pycache__', '.terraform', 'target',
]);

const MAX_FILE_BYTES = 8 * 1024 * 1024;

function* walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.env') {
      if (SKIP_DIRS.has(entry.name) || entry.isDirectory()) continue;
    }
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walk(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

/** Expand files and directories into a flat list of readable text files. */
function expand(targets) {
  const out = [];
  for (const target of targets) {
    let st;
    try {
      st = statSync(target);
    } catch {
      process.stderr.write(`pastesafe: cannot read ${target}: no such file\n`);
      process.exit(2);
    }
    if (st.isDirectory()) {
      for (const file of walk(target)) {
        const content = readTextSafe(file);
        if (content !== null) out.push({ label: file, text: content });
      }
    } else {
      const content = readTextSafe(target);
      out.push({ label: target, text: content ?? '' });
    }
  }
  return out;
}

/** Returns null for binary or oversized files, which we skip rather than mangle. */
function readTextSafe(path) {
  try {
    const st = statSync(path);
    if (st.size > MAX_FILE_BYTES) return null;
    const buf = readFileSync(path);
    if (buf.includes(0)) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

function installHook() {
  const hookPath = resolve('.git/hooks/pre-commit');
  if (!existsSync(resolve('.git'))) {
    process.stderr.write('pastesafe: not a git repository\n');
    process.exit(2);
  }
  const script = `#!/bin/sh
# Installed by pastesafe --install-hook
diff=$(git diff --cached --unified=0 --no-color)
if [ -n "$diff" ]; then
  printf '%s' "$diff" | npx --yes pastesafe --fail-on high - || {
    echo
    echo "PasteSafe: commit blocked. Fix the findings above, or bypass with --no-verify."
    exit 1
  }
fi
`;
  writeFileSync(hookPath, script);
  chmodSync(hookPath, 0o755);
  process.stdout.write(`Installed pre-commit hook at ${relative(process.cwd(), hookPath)}\n`);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  // With no arguments, an interactive shell means "the user needs help" but a
  // pipe means "the user is feeding us text".
  const stdinPiped = !process.stdin.isTTY;
  const noInput =
    !opts.files.length && opts.text === null && !opts.installHook && !stdinPiped;

  if (opts.help || noInput) {
    process.stdout.write(`${HELP}\n`);
    process.exit(opts.help ? 0 : 2);
  }
  if (opts.installHook) return installHook();

  if (opts.only) {
    for (const id of opts.only) {
      if (id !== 'generic.high-entropy' && !RULES_BY_ID.has(id)) {
        process.stderr.write(`pastesafe: unknown rule id "${id}"\n`);
        process.exit(2);
      }
    }
  }

  /** @type {{label: string, text: string}[]} */
  const sources = [];
  if (opts.text !== null) sources.push({ label: '<text>', text: opts.text });
  for (const file of opts.files) {
    if (file === '-') sources.push({ label: '<stdin>', text: readStdin() });
    else sources.push(...expand([file]));
  }
  if (sources.length === 0) sources.push({ label: '<stdin>', text: readStdin() });

  const all = [];
  const perSource = [];
  for (const { label, text } of sources) {
    const result = scan(text, {
      only: opts.only,
      skip: opts.skip,
      entropy: opts.entropy,
      verified: opts.verified,
    });
    // Every finding carries its origin so multi-file SARIF and JSON are usable.
    for (const f of result.findings) f.file = label;
    all.push(...result.findings);
    perSource.push({ label, text, result });
  }

  if (opts.redact) {
    for (const { text, result } of perSource) {
      const { text: safe } = redact(text, result.findings, opts.mode);
      process.stdout.write(safe);
      if (!safe.endsWith('\n')) process.stdout.write('\n');
    }
  } else if (opts.sarif) {
    process.stdout.write(`${JSON.stringify(toSarif(sources[0].label, all), null, 2)}\n`);
  } else if (opts.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          version: 1,
          summary: perSource.reduce(
            (acc, s) => ({
              total: acc.total + s.result.summary.total,
              distinctSecrets:
                acc.distinctSecrets +
                new Set(s.result.findings.map((f) => f.fingerprint)).size,
            }),
            { total: 0, distinctSecrets: 0 },
          ),
          findings: all,
        },
        null,
        2,
      )}\n`,
    );
  } else {
    const showFile = sources.length > 1;
    const blocks = perSource
      .filter((s) => s.result.findings.length)
      .map(
        (s) =>
          (showFile ? `${s.label}\n` : '') +
          formatText(s.text, s.result.findings, s.result.summary, {
            color: Boolean(process.stdout.isTTY),
          }),
      );
    if (blocks.length) process.stdout.write(`${blocks.join('\n\n')}\n`);
    else process.stdout.write('  CLEAN  no secrets or PII detected\n');
  }

  if (opts.failOn !== 'none') {
    const threshold = RANK[opts.failOn] ?? RANK.high;
    if (all.some((f) => RANK[f.severity] >= threshold)) process.exit(1);
  }
  process.exit(0);
}

main();

export { parseArgs, expand, readTextSafe };
