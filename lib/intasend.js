const CHECKOUT_URL = 'https://api.intasend.com/api/v1/checkout/';

// Creates a hosted IntaSend checkout session restricted to M-Pesa and returns
// the URL to redirect the customer to. Uses the publishable key per IntaSend's
// docs for this endpoint — the secret key is reserved for calls that need it
// (refunds, wallet, transaction status) and is never sent from the browser.
export async function createMpesaCheckout({ amount, currency, apiRef, email, redirectUrl }) {
  const res = await fetch(CHECKOUT_URL, {
    method: 'POST',
    headers: {
      'X-IntaSend-Public-API-Key': process.env.INTASEND_PUBLISHABLE_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      channel: 'WEBSITE',
      method: 'M-PESA',
      amount: String(amount),
      currency,
      api_ref: apiRef,
      email: email || undefined,
      country: 'KE',
      redirect_url: redirectUrl,
      mobile_tarrif: 'BUSINESS-PAYS',
    }),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(`IntaSend error (${res.status}): ${data.detail || JSON.stringify(data)}`);
  }
  return data; // { id, url, signature, ... }
}

// IntaSend webhooks don't sign the payload — they echo back a "challenge"
// string that you configure once in the IntaSend dashboard's webhook settings.
// Verification is just confirming the payload's challenge matches ours.
export function isValidIntaSendChallenge(payloadChallenge) {
  const expected = process.env.INTASEND_WEBHOOK_CHALLENGE;
  return !!expected && payloadChallenge === expected;
}
