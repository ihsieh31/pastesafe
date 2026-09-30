import { isEmail, isJwt, jwtExpiry, luhn, taiwanNationalId } from './validate.js';

/**
 * The rule set.
 *
 * Every rule declares:
 *   id         stable identifier, also used in `# pastesafe:allow <id>` comments
 *   category   'secret' | 'credential' | 'pii'
 *   severity   'critical' | 'high' | 'medium' | 'low'
 *   pattern    RegExp; capture group `group` (default 1) holds the redacted value
 *   validate   optional predicate; when it returns false the match is dropped
 *   confidence 'pattern' | 'verified' (checksum/structure actually validated)
 *
 * `group: 0` means "redact the whole match" — used when the surrounding context
 * is what makes something sensitive (e.g. a connection URI's password field).
 */

const KEYWORD = '(?:password|passwd|pwd|passphrase|secret|secrete|token|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|encryption[_-]?key|signing[_-]?key|session[_-]?key|master[_-]?key|credential)';

export const RULES = [
  // ── Private key material ────────────────────────────────────────────────
  {
    id: 'pem.private-key',
    category: 'secret',
    severity: 'critical',
    confidence: 'verified',
    message: 'PEM private key block',
    pattern:
      /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    group: 0,
  },

  // ── Cloud providers ─────────────────────────────────────────────────────
  {
    id: 'aws.access-key-id',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'AWS access key ID',
    pattern: /\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[0-9A-Z]{16})\b/g,
  },
  {
    id: 'aws.secret-access-key',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'AWS secret access key',
    pattern: new RegExp(
      `aws[_-]?(?:secret[_-]?)?access[_-]?key\\s*[:=]\\s*["']?([A-Za-z0-9/+=]{40})["']?`,
      'gi',
    ),
  },
  {
    id: 'gcp.api-key',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Google Cloud API key',
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
  },
  {
    id: 'azure.storage-key',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Azure storage account key',
    pattern: new RegExp(`AccountKey\\s*=\\s*([A-Za-z0-9+/]{86}==)`, 'g'),
  },

  // ── LLM providers ───────────────────────────────────────────────────────
  {
    id: 'anthropic.api-key',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Anthropic API key',
    pattern: /\b(sk-ant-[A-Za-z0-9_-]{24,})\b/g,
  },
  {
    id: 'openai.api-key',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'OpenAI API key',
    pattern: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})\b/g,
  },
  {
    id: 'openai.organization-key',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'OpenAI organisation key',
    pattern: /\b(org-[A-Za-z0-9]{24})\b/g,
  },
  {
    id: 'huggingface.token',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Hugging Face access token',
    pattern: /\b(hf_[A-Za-z0-9]{34,})\b/g,
  },
  {
    id: 'replicate.api-token',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Replicate API token',
    pattern: /\b(r8_[A-Za-z0-9]{37})\b/g,
  },
  {
    id: 'perplexity.api-key',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Perplexity API key',
    pattern: /\b(pplx-[A-Za-z0-9]{40,})\b/g,
  },

  // ── Source control & CI ─────────────────────────────────────────────────
  {
    id: 'github.pat',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'GitHub personal access token',
    pattern: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b/g,
  },
  {
    id: 'github.fine-grained-pat',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'GitHub fine-grained token',
    pattern: /\b(github_pat_[A-Za-z0-9_]{50,})\b/g,
  },
  {
    id: 'gitlab.pat',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'GitLab personal access token',
    pattern: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g,
  },
  {
    id: 'npm.token',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'npm access token',
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/g,
  },
  {
    id: 'pypi.token',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'PyPI upload token',
    pattern: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b/g,
  },

  // ── Payments & commerce ─────────────────────────────────────────────────
  {
    id: 'stripe.secret-key',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Stripe secret key',
    pattern: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b/g,
  },
  {
    id: 'stripe.webhook-secret',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Stripe webhook signing secret',
    pattern: /\b(whsec_[A-Za-z0-9]{32,})\b/g,
  },
  {
    id: 'shopify.access-token',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Shopify access token',
    pattern: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/g,
  },
  {
    id: 'square.access-token',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Square access token',
    pattern: /\b(sq0(?:atp|csp|idp)-[A-Za-z0-9_-]{22,})\b/g,
  },
  {
    id: 'paypal.braintree-token',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Braintree access token',
    pattern: /\b(access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32})\b/g,
  },

  // ── Messaging, comms & comms-ops ────────────────────────────────────────
  {
    id: 'slack.token',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Slack API token',
    pattern: /\b(xox[baprse]-[A-Za-z0-9-]{10,})\b/g,
  },
  {
    id: 'slack.webhook',
    category: 'secret',
    severity: 'medium',
    confidence: 'pattern',
    message: 'Slack incoming webhook URL',
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8,}\/B[A-Za-z0-9_]{8,}\/[A-Za-z0-9_]{20,})/g,
    group: 0,
  },
  {
    id: 'discord.bot-token',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Discord bot token',
    pattern: /\b([MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b/g,
  },
  {
    id: 'telegram.bot-token',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Telegram bot token',
    pattern: /\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b/g,
  },
  {
    id: 'twilio.account-sid',
    category: 'secret',
    severity: 'medium',
    confidence: 'pattern',
    message: 'Twilio account SID',
    pattern: /\b(AC[0-9a-fA-F]{32})\b/g,
  },
  {
    id: 'twilio.api-key',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Twilio API key SID',
    pattern: new RegExp(`\\b(SK[0-9a-fA-F]{32})\\b`, 'g'),
  },
  {
    id: 'sendgrid.api-key',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'SendGrid API key',
    pattern: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g,
  },
  {
    id: 'mailgun.api-key',
    category: 'secret',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Mailgun API key',
    pattern: /\b(key-[0-9a-fA-F]{32})\b/g,
  },
  {
    id: 'postmark.server-token',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Postmark server token',
    pattern: /\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/g,
    validate: (v) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v),
    // Postmark tokens are UUIDs, indistinguishable from any other UUID.
    // Flagged as `pattern` confidence so the UI can de-prioritise it.
  },

  // ── Infrastructure ──────────────────────────────────────────────────────
  {
    id: 'url.basic-auth',
    category: 'credential',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Credentials embedded in a URL',
    pattern: /\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@"']+:[^\s:/@"'?#]{3,}@[^\s"'`]+)/gi,
    group: 0,
  },
  {
    id: 'url.query-token',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Token passed in a URL query string',
    pattern: new RegExp(
      `\\b((?:${KEYWORD}|code|access_token|assertion|sig|signature)=[A-Za-z0-9._~+/%-]{16,})`,
      'gi',
    ),
  },
  {
    id: 'auth.bearer-header',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Bearer token in an authorization header',
    pattern: /\b(Bearer\s+[A-Za-z0-9._~+/=-]{20,})/g,
    group: 0,
  },
  {
    id: 'auth.basic-header',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Basic auth credentials',
    pattern: /\b(Basic\s+[A-Za-z0-9+/]{16,}={0,2})/g,
    group: 0,
  },
  {
    id: 'jwt.token',
    category: 'secret',
    severity: 'medium',
    confidence: 'verified',
    message: 'JSON Web Token',
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,})\b/g,
    validate: isJwt,
  },
  {
    id: 'db.connection-string',
    category: 'credential',
    severity: 'critical',
    confidence: 'pattern',
    message: 'Database connection string with a password',
    // The username is optional: `redis://:hunter2@cache` and
    // `postgres://admin:hunter2@db` are both common in the wild.
    pattern: /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|clickhouse):\/\/[^\s:/@]*:[^\s:/@]+@[^\s"'`]+)/gi,
    group: 0,
  },

  // ── Generic keyword assignment ──────────────────────────────────────────
  {
    id: 'generic.secret-assignment',
    category: 'secret',
    severity: 'high',
    confidence: 'pattern',
    message: 'Secret-looking value assigned to a credential-like name',
    pattern: new RegExp(
      `${KEYWORD}\\s*[:=]\\s*["']([^"'\\n]{8,120})["']`,
      'gi',
    ),
    // Skip obvious placeholders so we don't scream at every README.
    validate: (v) =>
      !/^(?:x{3,}|\*{3,}|\.{3,}|changeme|placeholder|your[_-]?\w+|example|dummy|none|null|undefined|todo|<[^>]+>|\$\{[^}]+\}|%[sdv]|process\.env[\w.]*|\{\{?[\w.]+\}?\})/i.test(
        v.trim(),
      ) && !/^\d+$/.test(v.trim()),
  },

  // ── PII ─────────────────────────────────────────────────────────────────
  {
    id: 'pii.credit-card',
    category: 'pii',
    severity: 'high',
    confidence: 'verified',
    message: 'Payment card number',
    pattern: /\b((?:\d[ -]?){12,18}\d)\b/g,
    validate: luhn,
  },
  {
    id: 'pii.taiwan-national-id',
    category: 'pii',
    severity: 'high',
    confidence: 'verified',
    message: 'Taiwan national ID number',
    pattern: /\b([A-Z][12]\d{8})\b/g,
    validate: taiwanNationalId,
  },
  {
    id: 'pii.us-ssn',
    category: 'pii',
    severity: 'high',
    confidence: 'pattern',
    message: 'US social security number',
    pattern: /\b((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})\b/g,
  },
  {
    id: 'pii.email',
    category: 'pii',
    severity: 'low',
    confidence: 'verified',
    message: 'Email address',
    pattern: /\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g,
    validate: isEmail,
  },
];

export const RULES_BY_ID = new Map(RULES.map((r) => [r.id, r]));

/** Rules that identify JWTs, re-exported so callers can check expiry. */
export { jwtExpiry };

export const CATEGORY_ORDER = ['secret', 'credential', 'pii'];
