#!/usr/bin/env node
/**
 * One command to turn a payout key into a live checkout link.
 *
 *   STRIPE_SECRET_KEY=sk_live_... node setup/launch.mjs
 *   node setup/launch.mjs --dry-run     # print the plan, touch nothing
 *
 * Nothing else is required: the product, the price and the payment link are all
 * created through the API, so there is no clicking through a dashboard.
 */

import process from 'node:process';

const OFFERS = [
  {
    name: 'PasteSafe — CLI',
    amount: 1900,
    currency: 'usd',
    description:
      'Lifetime licence for the PasteSafe CLI. Zero dependencies, MIT, all updates. ' +
      'Runs offline; nothing is uploaded or logged.',
  },
  {
    name: 'PasteSafe — Team licence',
    amount: 9900,
    currency: 'usd',
    description:
      'Up to 10 developers. Adds the SARIF pipeline for GitHub code scanning, ' +
      'the pre-commit hook installer, and a shared rules config.',
  },
  {
    name: 'Secret Exposure Audit',
    amount: 19900,
    currency: 'usd',
    description:
      'I scan your repository and its git history for leaked credentials, report ' +
      'every finding with severity and rotation steps, and hand you a written report.',
  },
];

async function stripe(path, body, key) {
  const res = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(body).toString(),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`${path}: ${json?.error?.message ?? res.status}`);
  return json;
}

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const key = process.env.STRIPE_SECRET_KEY;

  console.log('\nPasteSafe — checkout setup\n');

  if (!key) {
    console.log('No STRIPE_SECRET_KEY found. Here is what to do:\n');
    console.log('  1. Get a key from https://dashboard.stripe.com/apikeys');
    console.log('  2. Re-run with it:\n');
    console.log('     STRIPE_SECRET_KEY=sk_live_... node setup/launch.mjs\n');
    console.log('Payout country notes:');
    console.log('  · Taiwan (TW) is cross-border-payout only on Stripe, which needs a');
    console.log('    Connect platform. For an individual TW seller use Payoneer, PayPal TW,');
    console.log('    or a merchant-of-record platform (Gumroad / Lemon Squeezy) instead.');
    console.log('  · Use sk_test_… first to prove the flow, then switch to sk_live_…\n');
    process.exit(1);
  }

  const live = key.startsWith('sk_live_');
  if (live && !process.argv.includes('--yes-i-am-live')) {
    console.log('That is a LIVE key. Re-run with --yes-i-am-live to create real products.\n');
    process.exit(1);
  }
  if (!live && dryRun) {
    console.log('Using a test key, so the following is a simulation.\n');
  }

  const links = [];
  for (const offer of OFFERS) {
    if (dryRun) {
      console.log(`  would create  ${offer.name} — ${offer.amount / 100} ${offer.currency.toUpperCase()}`);
      continue;
    }
    const product = await stripe('products', {
      name: offer.name,
      description: offer.description,
      metadata: { product: 'pastesafe' },
    }, key);

    const price = await stripe('prices', {
      product: product.id,
      unit_amount: String(offer.amount),
      currency: offer.currency,
    }, key);

    const link = await stripe('payment_links', {
      'line_items[0][price]': price.id,
      'line_items[0][quantity]': '1',
      'after_completion[type]': 'redirect',
      'after_completion[redirect][url]': 'https://example.com/thanks',
    }, key);

    links.push({ name: offer.name, url: link.url });
    console.log(`  created  ${offer.name} → ${link.url}`);
  }

  if (links.length) {
    console.log(`\n${links.length} checkout link(s) are live.\n`);
    console.log('After a payment lands, Stripe pays out on your configured schedule.');
    console.log('Check the balance at https://dashboard.stripe.com/balance\n');
  }
  process.exit(0);
}

main().catch((err) => {
  console.error(`\nlaunch failed: ${err.message}\n`);
  process.exit(1);
});
