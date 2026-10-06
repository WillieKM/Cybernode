// api/intasend-checkout.js
// Creates an IntaSend M-Pesa checkout session for the KES 5,000 scan-report
// unlock (the Kenya-priced alternative to the $19 Stripe flow — Stripe can't
// collect KES or M-Pesa at all). Stashes { domain, email } in Redis keyed by
// a short order id, since IntaSend's api_ref field can't hold a raw email
// address (alphanumeric + "-_: " only) — the webhook looks the order back up
// by that id once payment completes.
// ----------------------------------------------------------------
// SETUP:
// 1. Create an account at https://intasend.com (start in sandbox/test mode —
//    test keys are prefixed ISPubKey_test_ / ISSecretKey_test_).
// 2. Dashboard -> Settings -> API Keys -> copy the Publishable key.
//    In Vercel -> Project -> Settings -> Environment Variables, set:
//      INTASEND_PUBLISHABLE_KEY = ISPubKey_...
// 3. Dashboard -> Settings -> Webhooks -> add endpoint:
//      https://www.cyber-node.com/api/intasend-webhook
//    Set a "challenge" string there (any secret string you choose), then set
//    the same value in Vercel:
//      INTASEND_WEBHOOK_CHALLENGE = <that same string>
// 4. Already-configured UPSTASH_REDIS_REST_URL / _TOKEN (used by the Stripe
//    flow) are reused here — no separate Redis setup needed.
// 5. Switch to live keys the same way once sandbox checkouts confirm the
//    PDF + email actually arrive end to end.
// ----------------------------------------------------------------

import { randomBytes } from 'crypto';
import { Redis } from '@upstash/redis';
import { createMpesaCheckout } from '../lib/intasend.js';
import { isSafeDomain } from '../lib/scan-domain.js';
import { captureError } from '../lib/sentry.js';

const redis = process.env.UPSTASH_REDIS_REST_URL
  ? new Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN })
  : null;

const PRICE_KES = '5000.00';
const ORDER_TTL_SECONDS = 60 * 60 * 24; // 24h is plenty to complete an M-Pesa prompt

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { domain, email } = req.body || {};
  const cleanDomain = String(domain || '').trim().toLowerCase();
  const cleanEmail = String(email || '').trim();

  if (!isSafeDomain(cleanDomain)) {
    return res.status(400).json({ error: 'Enter a valid public domain, e.g. example.com' });
  }
  if (!cleanEmail || !cleanEmail.includes('@')) {
    return res.status(400).json({ error: 'A valid email is required to receive the report.' });
  }
  if (!redis) {
    return res.status(500).json({ error: 'Payment is temporarily unavailable — please try again shortly.' });
  }

  const orderId = randomBytes(8).toString('hex');
  await redis.set(`intasend-order:${orderId}`, { domain: cleanDomain, email: cleanEmail }, { ex: ORDER_TTL_SECONDS });

  try {
    const checkout = await createMpesaCheckout({
      amount: PRICE_KES,
      currency: 'KES',
      apiRef: `KE_${orderId}`,
      email: cleanEmail,
      redirectUrl: 'https://www.cyber-node.com/tools/security-scan.html',
    });
    return res.status(200).json({ url: checkout.url });
  } catch (err) {
    console.error('IntaSend checkout creation failed:', err.message);
    captureError(err, { domain: cleanDomain });
    return res.status(502).json({ error: 'Could not start M-Pesa checkout — please try again.' });
  }
}
