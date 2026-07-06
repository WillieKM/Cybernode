import Stripe from 'stripe';
import { runScan } from '../lib/scan-domain.js';
import { generateReportPDF } from '../lib/generate-report-pdf.js';
import { sendReportEmail } from '../lib/send-report-email.js';

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

  try {
    // isSafeDomain check inside runScan rejects IP literals and private ranges
    // to prevent SSRF via a buyer who typed e.g. 169.254.169.254 as their "domain"
    const scan = await runScan(domain);
    const pdfBuffer = await generateReportPDF(scan);
    await sendReportEmail({ to: email, domain, pdfBuffer });
    console.log(`Report sent for ${domain} to ${email} (session ${session.id})`);
  } catch (err) {
    console.error(`Fulfillment failed for session ${session.id}:`, err.message);
    // Still ack the webhook — Stripe payment already succeeded; this failure
    // needs to surface via logs/monitoring, not a Stripe retry of the payment event.
  }

  return res.status(200).json({ received: true });
}
