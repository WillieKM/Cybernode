// api/scan.js
// Vercel serverless function — powers the free instant preview on
// /tools/security-scan.html. Runs the exact same non-intrusive DNS/TLS/header/port
// checks that the paid $19 PDF report uses (see lib/scan-domain.js), but returns a
// summarized subset — full header names, port list, and remediation steps stay
// behind the paid report generated in api/stripe-webhook.js.

import { Redis } from '@upstash/redis';
import { runScan, computeScore, isSafeDomain } from '../lib/scan-domain.js';

const redis = process.env.UPSTASH_REDIS_REST_URL
  ? new Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN })
  : null;

const RATE_LIMIT = 8;                // free scans allowed per IP
const RATE_WINDOW_SECONDS = 60 * 60; // per rolling hour

async function checkRateLimit(ip) {
  if (!redis) return true; // Redis not configured (e.g. local dev) — don't block
  try {
    const key = `scan-rate:${ip}`;
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, RATE_WINDOW_SECONDS);
    return count <= RATE_LIMIT;
  } catch (err) {
    // Redis unreachable — fail open so a Redis outage doesn't take down the
    // free scan tool entirely; just means rate limiting is temporarily off.
    console.error('rate limit check failed, allowing request:', err.message);
    return true;
  }
}

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const domain = String(req.query.domain || '').trim().toLowerCase();
  if (!isSafeDomain(domain)) {
    return res.status(400).json({ error: 'Enter a valid public domain, e.g. example.com' });
  }

  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();

  const allowed = await checkRateLimit(ip);
  if (!allowed) {
    return res.status(429).json({ error: 'Too many scans from this address — try again in an hour.' });
  }

  try {
    const scan = await runScan(domain);
    const score = computeScore(scan);

    const headerEntries = Object.entries(scan.headers?.headers || {});
    const missingHeaders = headerEntries.filter(([, v]) => !v).length;
    const openPorts = Object.values(scan.ports || {}).filter((p) => p.open).length;

    res.status(200).json({
      domain: scan.domain,
      ip: scan.dns?.a?.[0] || null,
      score: score.score,
      rating: score.rating,
      ssl: {
        valid: !!scan.ssl?.valid,
        daysRemaining: scan.ssl?.daysRemaining ?? null,
      },
      headers: {
        reachable: !!scan.headers?.reachable,
        missing: missingHeaders,
        total: headerEntries.length,
      },
      exposureSignals: openPorts, // count only — which ports stay behind the paid report
      scannedAt: scan.scannedAt,
    });
  } catch (err) {
    console.error('scan failed:', err.message);
    res.status(502).json({ error: 'Scan failed — the target may be unreachable or blocking automated requests.' });
  }
}
