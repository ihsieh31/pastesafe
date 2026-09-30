import { test } from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../src/scanner.js';
import { redact, previewLine } from '../src/redact.js';
import { toSarif } from '../src/sarif.js';
import { luhn, taiwanNationalId, isEmail, isJwt } from '../src/validate.js';
import { shannon, looksRandom } from '../src/entropy.js';

const SAMPLE = `Here is my config:

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DB_URL=postgres://admin:hunter2@db.internal:5432/prod
openai = "sk-proj-abc123def456ghi789jkl012mno345"
card: 4242 4242 4242 4242
`;

test('redaction removes every secret from the output', () => {
  const { findings } = scan(SAMPLE);
  const { text: safe } = redact(SAMPLE, findings);

  for (const secret of [
    'AKIAIOSFODNN7EXAMPLE',
    'hunter2',
    'sk-proj-abc123def456ghi789jkl012mno345',
    '4242 4242 4242 4242',
  ]) {
    assert.equal(safe.includes(secret), false, `leaked: ${secret}`);
  }
  assert.ok(safe.includes('«aws.access-key-id#'), 'placeholders are present');
});

test('redaction keeps the text otherwise intact', () => {
  const { findings } = scan(SAMPLE);
  const { text: safe } = redact(SAMPLE, findings);
  assert.ok(safe.includes('Here is my config:'));
  assert.ok(safe.includes('DB_URL='));
  assert.ok(safe.length > 0);
});

test('full mode produces a uniform placeholder', () => {
  const { findings } = scan(SAMPLE);
  const { text: safe } = redact(SAMPLE, findings, 'full');
  assert.equal(safe.includes('[REDACTED]'), true);
});

test('preview never contains the secret', () => {
  const { findings } = scan(SAMPLE);
  for (const f of findings) {
    const preview = previewLine(SAMPLE, f);
    assert.equal(preview.includes(SAMPLE.slice(f.start, f.end)), false, `leaked in preview: ${f.id}`);
  }
});

test('redaction is not reversible from the placeholder', () => {
  const { findings } = scan(SAMPLE);
  const { text: safe } = redact(SAMPLE, findings);
  const [f] = findings;
  assert.equal(safe.includes(f.fingerprint), true);
  assert.equal(safe.includes(SAMPLE.slice(f.start, f.end)), false);
});

test('sarif output is valid enough for GitHub code scanning', () => {
  const { findings } = scan(SAMPLE);
  const sarif = toSarif('config.txt', findings);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, 'PasteSafe');
  assert.equal(sarif.runs[0].results.length, findings.length);
  const first = sarif.runs[0].results[0];
  assert.ok(first.ruleId);
  assert.ok(['error', 'warning', 'note'].includes(first.level));
  assert.ok(first.locations[0].physicalLocation.region.startLine >= 1);
  // Uploading a SARIF to a public repo must not leak the secret.
  assert.equal(JSON.stringify(sarif).includes('AKIAIOSFODNN7EXAMPLE'), false);
});

test('luhn accepts real PANs and rejects typos', () => {
  assert.equal(luhn('4242424242424242'), true);
  assert.equal(luhn('4242424242424243'), false);
  assert.equal(luhn('not-a-card'), false);
});

test('taiwan national id checksum', () => {
  assert.equal(taiwanNationalId('A123456789'), true);
  assert.equal(taiwanNationalId('A123456780'), false);
  assert.equal(taiwanNationalId('1234567890'), false);
});

test('email and jwt validators', () => {
  assert.equal(isEmail('dev@example.com'), true);
  assert.equal(isEmail('dev@localhost'), false);
  assert.equal(isEmail('a..b@example.com'), false);
  assert.equal(isJwt('a.b.c'), false);
});

test('entropy helpers behave', () => {
  assert.equal(shannon('aaaaaaaa'), 0);
  assert.ok(shannon('AKIAIOSFODNN7EXAMPLE') > 3);
  assert.equal(looksRandom('aaaaaaaaaaaaaaaaaaaaaaaa'), false);
  assert.equal(looksRandom('AKIAIOSFODNN7EXAMPLE'), true);
});

test('high-entropy rule catches unknown provider secrets', () => {
  const secret = 'Zk3Q9xLm2Vp7Rt4Yw8Nb6Hc1Jf5Dg0Sa3';
  const { findings } = scan(`const cfg = "${secret}";`);
  assert.ok(findings.some((f) => f.id === 'generic.high-entropy'));
});

test('a specific rule wins over the entropy catch-all', () => {
  // The token `AWS_ACCESS_KEY_ID=AKIA...` is high entropy as a whole, but the
  // precise finding is more useful and leaves the variable name readable.
  const { findings } = scan('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
  assert.equal(findings[0].id, 'aws.access-key-id');
  const { text: safe } = redact('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', findings);
  assert.ok(safe.startsWith('AWS_ACCESS_KEY_ID='));
});

test('the entropy rule can be switched off', () => {
  const secret = 'Zk3Q9xLm2Vp7Rt4Yw8Nb6Hc1Jf5Dg0Sa3';
  const { findings } = scan(`MY_SERVICE_CREDENTIAL="${secret}"`, { entropy: false });
  assert.equal(findings.some((f) => f.id === 'generic.high-entropy'), false);
});

test('scanning is linear-ish on a large input', () => {
  const big = SAMPLE.repeat(400);
  const started = Date.now();
  const { findings } = scan(big);
  const ms = Date.now() - started;
  assert.ok(findings.length > 100);
  assert.ok(ms < 5000, `too slow: ${ms}ms`);
});
