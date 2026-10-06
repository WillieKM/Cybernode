// api/intasend-webhook.js
// Fulfillment for the M-Pesa scan-report unlock: IntaSend POSTs here when a
// checkout's state changes. Unlike Stripe, IntaSend doesn't sign the payload —
// it echoes back a "challenge" string configured once in the IntaSend
// dashboard's webhook settings, so verification is just comparing that value.

import { Redis } from '@upstash/redis';
import { runScan } from '../lib/scan-domain.js';
import { generateReportPDF } from '../lib/generate-report-pdf.js';
import { sendReportEmail } from '../lib/send-report-email.js';
import { isValidIntaSendChallenge } from '../lib/intasend.js';
import { initSentry, captureError } from '../lib/sentry.js';

initSentry();

const redis = process.env.UPSTASH_REDIS_REST_URL
  ? new Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN })
  : null;

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const event = req.body || {};

  if (!isValidIntaSendChallenge(event.challenge)) {
    console.error('IntaSend webhook: challenge mismatch — rejecting');
    return res.status(400).json({ error: 'Invalid challenge' });
  }

  if (event.state !== 'COMPLETE') {
    return res.status(200).json({ received: true, skipped: `state=${event.state}` });
  }

  const apiRef = String(event.api_ref || '');
  if (!apiRef.startsWith('KE_')) {
    return res.status(200).json({ received: true, skipped: 'not a scan-report order' });
  }
  const orderId = apiRef.slice('KE_'.length);

  if (!redis) {
    console.error('IntaSend webhook received but Redis is not configured — cannot fulfill');
    return res.status(200).json({ received: true, skipped: 'no redis' });
  }

  // Idempotency — IntaSend retries webhooks up to 6 times on non-2xx/timeout;
  // don't send the report twice for the same invoice.
  const dedupeKey = `intasend-webhook:${event.invoice_id}`;
  const alreadyProcessed = await redis.get(dedupeKey);
  if (alreadyProcessed) {
    return res.status(200).json({ received: true, skipped: 'already processed' });
  }
  await redis.set(dedupeKey, '1', { ex: 60 * 60 * 24 * 7 });

  const order = await redis.get(`intasend-order:${orderId}`);
  if (!order) {
    console.error(`IntaSend webhook: no pending order found for ${orderId}`);
    return res.status(200).json({ received: true, skipped: 'order not found' });
  }

  try {
    const scan = await runScan(order.domain);
    const pdfBuffer = await generateReportPDF(scan);
    await sendReportEmail({ to: order.email, domain: order.domain, pdfBuffer });
    console.log(`IntaSend report sent for ${order.domain} to ${order.email} (invoice ${event.invoice_id})`);
  } catch (err) {
    console.error(`IntaSend fulfillment failed for order ${orderId}:`, err.message);
    captureError(err, { orderId, domain: order.domain });
    // Still ack the webhook — payment already succeeded; failure needs to
    // surface via Sentry/logs, not an IntaSend retry of the payment event.
  }

  return res.status(200).json({ received: true });
}
