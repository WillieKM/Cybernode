// scripts/batch-scan.mjs
// Internal prospecting tool — NOT part of the deployed site (nothing routes to it).
// Runs the same real, non-intrusive scan used by the paid report (lib/scan-domain.js)
// against a list of domains and writes a sortable CSV of results.
//
// Usage:
//   node scripts/batch-scan.mjs [input.csv] [output.csv]
//
// Input CSV format:  name,domain          (header row required)
// Output CSV adds:   score,rating,ssl_valid,ssl_days_remaining,headers_missing,headers_total,open_ports,top_reason
//
// Runs a handful of scans at a time (not all at once) so this behaves like an
// ordinary visitor loading a handful of pages in parallel, not a stress test —
// same spirit as the SSRF/private-IP guard already in isSafeDomain().

import { readFileSync, writeFileSync } from 'fs';
import { runScan, computeScore, isSafeDomain } from '../lib/scan-domain.js';

const CONCURRENCY = 4;
const DELAY_BETWEEN_BATCHES_MS = 1500;

const inputPath = process.argv[2] || 'scripts/sacco-domains.csv';
const outputPath = process.argv[3] || 'scripts/sacco-scan-results.csv';

function parseCsv(text) {
  return text
    .trim()
    .split('\n')
    .slice(1) // drop header
    .map((line) => line.split(','))
    .filter((cols) => cols.length >= 2)
    .map(([name, domain]) => ({ name: name.trim(), domain: domain.trim() }));
}

function csvEscape(value) {
  const s = String(value ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

async function scanOne({ name, domain }) {
  if (!isSafeDomain(domain)) {
    return { name, domain, error: 'invalid or unsafe domain — skipped' };
  }
  try {
    const scan = await runScan(domain);
    const score = computeScore(scan);
    const headerEntries = Object.entries(scan.headers?.headers || {});
    const missingHeaders = headerEntries.filter(([, v]) => !v).length;
    const openPorts = Object.values(scan.ports || {}).filter((p) => p.open).length;

    return {
      name,
      domain,
      score: score.score,
      rating: score.rating,
      ssl_valid: scan.ssl?.valid ? 'yes' : 'no',
      ssl_days_remaining: scan.ssl?.daysRemaining ?? '',
      headers_missing: missingHeaders,
      headers_total: headerEntries.length,
      open_ports: openPorts,
      top_reason: score.reasons[0] || '',
    };
  } catch (err) {
    return { name, domain, error: err.message };
  }
}

async function main() {
  const targets = parseCsv(readFileSync(inputPath, 'utf8'));
  console.error(`Scanning ${targets.length} domain(s) from ${inputPath}, ${CONCURRENCY} at a time...`);

  const results = [];
  const batches = chunk(targets, CONCURRENCY);
  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    console.error(`  batch ${i + 1}/${batches.length}: ${batch.map((t) => t.domain).join(', ')}`);
    const batchResults = await Promise.all(batch.map(scanOne));
    results.push(...batchResults);
    if (i < batches.length - 1) await new Promise((r) => setTimeout(r, DELAY_BETWEEN_BATCHES_MS));
  }

  const header = 'name,domain,score,rating,ssl_valid,ssl_days_remaining,headers_missing,headers_total,open_ports,top_reason,error';
  const rows = results.map((r) =>
    [r.name, r.domain, r.score, r.rating, r.ssl_valid, r.ssl_days_remaining, r.headers_missing, r.headers_total, r.open_ports, r.top_reason, r.error]
      .map(csvEscape)
      .join(',')
  );

  writeFileSync(outputPath, [header, ...rows].join('\n') + '\n');

  const failed = results.filter((r) => r.error).length;
  console.error(`Done. ${results.length - failed} scanned, ${failed} failed. Results written to ${outputPath}`);
}

main();
