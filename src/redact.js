import { SEVERITY_RANK } from './scanner.js';

/**
 * Turn findings into a safe copy of the original text.
 *
 * The core guarantee: **no output of this module ever contains the raw secret.**
 * Even the per-finding `preview` used in terminal reports is redacted, so piping
 * a report into a bug tracker or a CI log cannot become the second leak.
 */

/** @param {'fingerprint'|'mask'|'full'} mode */
function placeholder(finding, mode) {
  if (mode === 'full') return '[REDACTED]';
  const tag = `${finding.id}#${finding.fingerprint}`;
  if (mode === 'mask') {
    const tail = finding.tail ?? '';
    return tail ? `«${tag}:…${tail}»` : `«${tag}»`;
  }
  return `«${tag}»`;
}

/**
 * Replace every finding span in `text`.
 *
 * @returns {{ text: string, redacted: number, bytesSaved: number }}
 */
export function redact(text, findings, mode = 'fingerprint') {
  if (!findings.length) return { text, redacted: 0, bytesSaved: 0 };

  const ordered = [...findings].sort((a, b) => b.start - a.start);
  let out = text;
  let redacted = 0;

  for (const f of ordered) {
    out = out.slice(0, f.start) + placeholder(f, mode) + out.slice(f.end);
    redacted += 1;
  }

  return { text: out, redacted, bytesSaved: text.length - out.length };
}

/** The source line containing a finding, with the secret already removed. */
export function previewLine(text, finding, mode = 'fingerprint', context = 60) {
  const lineStart = text.lastIndexOf('\n', finding.start) + 1;
  let lineEnd = text.indexOf('\n', finding.start);
  if (lineEnd === -1) lineEnd = text.length;

  const line = text.slice(lineStart, lineEnd);
  const relStart = finding.start - lineStart;
  const relEnd = relStart + (finding.end - finding.start);
  const safe = line.slice(0, relStart) + placeholder(finding, mode) + line.slice(relEnd);

  // Trim very long lines but never cut through the redaction marker.
  if (safe.length <= context * 2) return safe.trim();
  const markerAt = safe.indexOf(placeholder(finding, mode));
  const from = Math.max(0, markerAt - context);
  const to = Math.min(safe.length, markerAt + context);
  return `${from > 0 ? '…' : ''}${safe.slice(from, to)}${to < safe.length ? '…' : ''}`;
}

const COLOR = process.env.NO_COLOR ? null : {
  critical: '\x1b[1;31m',
  high: '\x1b[31m',
  medium: '\x1b[33m',
  low: '\x1b[36m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  green: '\x1b[32m',
  reset: '\x1b[0m',
};

function paint(text, color) {
  return COLOR && color ? `${COLOR[color]}${text}${COLOR.reset}` : text;
}

/** Human-readable terminal report. Never prints a secret. */
export function formatText(text, findings, summary, { color = true } = {}) {
  const c = color ? COLOR : null;
  const p = (s, k) => (c ? paint(s, k) : s);
  const lines = [];

  const ordered = [...findings].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.line - b.line,
  );

  for (const f of ordered) {
    const head = `  ${p(f.severity.toUpperCase().padEnd(8), f.severity)} ${p(f.id, 'bold')}`;
    const loc = p(`${f.line}:${f.column}`, 'dim');
    const conf = f.confidence === 'verified' ? p(' verified', 'green') : '';
    lines.push(`${head} ${loc}${conf}`);
    lines.push(`           ${p(f.message, 'dim')}`);
    lines.push(`           ${p(previewLine(text, f), 'dim')}`);
  }

  if (!findings.length) {
    lines.push(`  ${p('CLEAN', 'green')}  no secrets or PII detected in ${summary.bytes} bytes`);
  }

  return lines.join('\n');
}
