import { test } from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../src/scanner.js';
import { RULES_BY_ID } from '../src/detectors.js';

const ids = (text, opts) => scan(text, { entropy: false, ...opts }).findings.map((f) => f.id);

test('detects provider-prefixed API keys', () => {
  assert.ok(ids('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE').includes('aws.access-key-id'));
  assert.ok(ids('OPENAI_KEY=sk-proj-abc123def456ghi789jkl012mno345').includes('openai.api-key'));
  assert.ok(ids('key = "sk-ant-api03-xyzABCdef012GHIjklMNOpqr456"').includes('anthropic.api-key'));
  assert.ok(ids('AIza' + 'A'.repeat(35)).includes('gcp.api-key'));
  assert.ok(ids('ghp_' + 'a'.repeat(36)).includes('github.pat'));
  assert.ok(ids('glpat-' + 'b'.repeat(20)).includes('gitlab.pat'));
  assert.ok(ids('npm_' + 'c'.repeat(36)).includes('npm.token'));
  assert.ok(ids('sk_live_' + 'd'.repeat(24)).includes('stripe.secret-key'));
  assert.ok(ids('xoxb-1234567890-abcdefghijkl').includes('slack.token'));
  assert.ok(ids('123456789:AA' + 'e'.repeat(33)).includes('telegram.bot-token'));
});

test('detects PEM private key headers', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow...';
  assert.ok(ids(pem).includes('pem.private-key'));
});

test('detects credentials embedded in URLs', () => {
  // The scheme-specific rule wins over the generic URL rule for the same span.
  assert.ok(ids('postgres://admin:hunter2@db.internal:5432/app').includes('db.connection-string'));
  // An empty username (`redis://:pass@host`) is still a credential.
  assert.ok(ids('redis://:mypassword@cache:6379').includes('db.connection-string'));
  // Non-database schemes fall through to the generic rule.
  assert.ok(ids('https://admin:hunter2@internal.example.com/x').includes('url.basic-auth'));
  // A port is not a password.
  assert.equal(ids('http://example.com:8080/path').includes('url.basic-auth'), false);
});

test('detects generic keyword assignments but skips placeholders', () => {
  assert.ok(ids('password = "s3cr3t-value-here"').includes('generic.secret-assignment'));
  assert.ok(ids('password = "changeme"').includes('generic.secret-assignment') === false);
  assert.ok(ids('api_key = "${API_KEY}"').includes('generic.secret-assignment') === false);
  assert.ok(ids('token: "your_token_here"').includes('generic.secret-assignment') === false);
});

test('credit cards require a valid Luhn checksum', () => {
  // 4242... is the canonical valid test PAN; the deliberately broken one is not.
  assert.ok(ids('card 4242 4242 4242 4242').includes('pii.credit-card'));
  assert.equal(ids('card 4242 4242 4242 4243').includes('pii.credit-card'), false);
});

test('taiwan national IDs require a valid checksum', () => {
  assert.ok(ids('身分證 A123456789').includes('pii.taiwan-national-id'));
  assert.equal(ids('身分證 A123456780').includes('pii.taiwan-national-id'), false);
});

test('verifies JWT structure', () => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: '123', exp: 1 })).toString('base64url');
  assert.ok(ids(`token ${header}.${payload}.c2lnbmF0dXJl`).includes('jwt.token'));
  assert.equal(ids('not.a.jwt.at.all').includes('jwt.token'), false);
});

test('reports line and column correctly', () => {
  const text = 'line one\nline two\nconst k = "AKIAIOSFODNN7EXAMPLE";\n';
  const [f] = scan(text, { entropy: false }).findings;
  assert.equal(f.line, 3);
  assert.equal(f.column, 12);
});

test('the raw secret is never exposed on a finding object', () => {
  const a = scan('AKIAIOSFODNN7EXAMPLE', { entropy: false }).findings[0];
  const b = scan('... AKIAIOSFODNN7EXAMPLE ...', { entropy: false }).findings[0];
  assert.equal(a.fingerprint, b.fingerprint);
  assert.equal('secret' in a, false);
  assert.equal(JSON.stringify(a).includes('AKIAIOSFODNN7EXAMPLE'), false);
});

test('the same key in two places collapses to one distinct secret', () => {
  const text = 'a: AKIAIOSFODNN7EXAMPLE\nb: AKIAIOSFODNN7EXAMPLE\n';
  const { findings, summary } = scan(text, { entropy: false });
  assert.equal(findings.length, 2);
  assert.equal(summary.distinctSecrets, 1);
});

test('honours pastesafe:allow directives', () => {
  const all = 'const k = "AKIAIOSFODNN7EXAMPLE"; # pastesafe:allow';
  assert.equal(scan(all, { entropy: false }).findings.length, 0);

  const one = 'const k = "AKIAIOSFODNN7EXAMPLE"; // pastesafe:allow:aws.access-key-id';
  assert.equal(scan(one, { entropy: false }).findings.length, 0);

  const wrongRule = 'const k = "AKIAIOSFODNN7EXAMPLE"; // pastesafe:allow:openai.api-key';
  assert.equal(scan(wrongRule, { entropy: false }).findings.length, 1);
});

test('--only and --skip filter rules', () => {
  const text = 'AKIAIOSFODNN7EXAMPLE and 4242 4242 4242 4242';
  assert.deepEqual(ids(text, { only: ['aws.access-key-id'] }), ['aws.access-key-id']);
  assert.deepEqual(ids(text, { skip: ['aws.access-key-id'] }), ['pii.credit-card']);
});

test('--verified keeps only checksum-backed rules', () => {
  const text = 'AKIAIOSFODNN7EXAMPLE and 4242 4242 4242 4242';
  const result = ids(text, { verified: true });
  assert.ok(result.includes('pii.credit-card'));
  assert.equal(result.includes('aws.access-key-id'), false);
});

test('overlapping matches are collapsed, strongest rule wins', () => {
  const text = 'Authorization: Bearer ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const result = scan(text, { entropy: false });
  const idsOnLine = result.findings.map((f) => f.id);
  assert.ok(idsOnLine.includes('github.pat') || idsOnLine.includes('auth.bearer-header'));
  assert.equal(new Set(idsOnLine).size, idsOnLine.length, 'no duplicate overlapping rules');
});

test('clean text produces no findings', () => {
  const text = 'const total = items.reduce((a, b) => a + b.price, 0);';
  assert.equal(scan(text).findings.length, 0);
});

test('every rule id referenced in tests exists in the registry', () => {
  for (const id of ['aws.access-key-id', 'openai.api-key', 'generic.secret-assignment', 'jwt.token']) {
    assert.ok(RULES_BY_ID.has(id), `missing rule ${id}`);
  }
});
