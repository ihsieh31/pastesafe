/**
 * SARIF 2.1.0 emitter, so findings upload straight to GitHub code scanning
 * (or any SARIF-consuming CI viewer) with no extra glue.
 */

const TOOL_URI = 'https://github.com/pastesafe/pastesafe';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };

const CWE = {
  'pem.private-key': 'CWE-321',
  'aws.access-key-id': 'CWE-798',
  'aws.secret-access-key': 'CWE-798',
  'gcp.api-key': 'CWE-798',
  'azure.storage-key': 'CWE-798',
  'anthropic.api-key': 'CWE-798',
  'openai.api-key': 'CWE-798',
  'github.pat': 'CWE-798',
  'gitlab.pat': 'CWE-798',
  'npm.token': 'CWE-798',
  'pypi.token': 'CWE-798',
  'url.basic-auth': 'CWE-798',
  'db.connection-string': 'CWE-798',
  'auth.bearer-header': 'CWE-798',
  'generic.secret-assignment': 'CWE-798',
  'generic.high-entropy': 'CWE-798',
  'pii.credit-card': 'CWE-311',
  'pii.taiwan-national-id': 'CWE-359',
  'pii.us-ssn': 'CWE-359',
  'pii.email': 'CWE-359',
};

/**
 * @param {string} uri               file path as the findings refer to it
 * @param {object[]} findings
 * @returns {object} SARIF log
 */
export function toSarif(uri, findings) {
  const rules = new Map();
  for (const f of findings) {
    if (rules.has(f.id)) continue;
    rules.set(f.id, {
      id: f.id,
      name: f.id.replace(/[.-]/g, ''),
      shortDescription: { text: f.message },
      fullDescription: { text: `${f.message} (${f.category})` },
      defaultConfiguration: { level: LEVEL[f.severity] ?? 'warning' },
      properties: {
        category: f.category,
        ...(CWE[f.id] ? { tags: [CWE[f.id], f.category] } : { tags: [f.category] }),
      },
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'PasteSafe',
            informationUri: TOOL_URI,
            version: '1.0.0',
            rules: [...rules.values()],
          },
        },
        results: findings.map((f) => ({
          ruleId: f.id,
          level: LEVEL[f.severity] ?? 'warning',
          message: { text: f.message },
          // Fingerprint is derived from the secret, never the secret itself, so
          // uploaded reports stay safe to make public.
          partialFingerprints: { secretFingerprint: f.fingerprint },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri },
                region: {
                  startLine: f.line,
                  startColumn: f.column,
                  endLine: f.endLine,
                  endColumn: f.endColumn,
                },
              },
            },
          ],
        })),
      },
    ],
  };
}
