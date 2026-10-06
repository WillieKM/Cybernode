import Stripe from 'stripe';
import { Redis } from '@upstash/redis';
import { runScan } from '../lib/scan-domain.js';
import { generateReportPDF } from '../lib/generate-report-pdf.js';
import { sendReportEmail } from '../lib/send-report-email.js';
import { initSentry, captureError } from '../lib/sentry.js';

initSentry();

const redis = process.env.UPSTASH_REDIS_REST_URL
  ? new Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN })
  : null;

// Stripe signature verification needs the exact raw request bytes — Vercel's
// default body parsing would re-serialize JSON and break the signature check.
export const config = { api: { bodyParser: false } };

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

async function getRawBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const rawBody = await getRawBody(req);
  const signature = req.headers['stripe-signature'];

  let event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type !== 'checkout.session.completed') {
    return res.status(200).json({ received: true });
  }

  const session = event.data.object;

  if (session.payment_status !== 'paid') {
    return res.status(200).json({ received: true, skipped: 'not paid' });
  }

  const refId = session.client_reference_id;
  const email = session.customer_details?.email || session.customer_email;

  if (!refId || !email) {
    console.error('checkout.session.completed missing client_reference_id or email', session.id);
    return res.status(200).json({ received: true, skipped: 'missing domain or email' });
  }

  const domain = refId.replace(/_/g, '.');

  // Idempotency check — if Stripe retries the webhook (timeout, network blip),
  // skip re-processing so the customer doesn't receive the report twice.
  // Wrapped in try/catch and fails open: a Redis outage shouldn't mean a
  // paying customer never gets their report, just a small risk of a dupe.
  if (redis) {
    try {
      const alreadyProcessed = await redis.get(`webhook:${session.id}`);
      if (alreadyProcessed) {
        console.log(`Session ${session.id} already processed — skipping`);
        return res.status(200).json({ received: true, skipped: 'already processed' });
      }
      await redis.set(`webhook:${session.id}`, '1', { ex: 60 * 60 * 24 * 7 }); // expire after 7 days
    } catch (err) {
      console.error('Redis idempotency check failed, proceeding anyway:', err.message);
    }
  }

  try {
    // isSafeDomain check inside runScan rejects IP literals and private ranges
    // to prevent SSRF via a buyer who typed e.g. 169.254.169.254 as their "domain"
    const scan = await runScan(domain);
    const pdfBuffer = await generateReportPDF(scan);
    await sendReportEmail({ to: email, domain, pdfBuffer });
    console.log(`Report sent for ${domain} to ${email} (session ${session.id})`);
  } catch (err) {
    console.error(`Fulfillment failed for session ${session.id}:`, err.message);
    captureError(err, { sessionId: session.id, domain });
    // Still ack the webhook — Stripe payment already succeeded; this failure
    // needs to surface via Sentry/logs, not a Stripe retry of the payment event.
  }

  return res.status(200).json({ received: true });
}
