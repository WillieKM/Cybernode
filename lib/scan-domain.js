import dns from 'dns/promises';
import tls from 'tls';
import net from 'net';

export async function checkDNS(domain) {
  const [a, mx, txt, ns] = await Promise.all([
    dns.resolve4(domain).catch(() => []),
    dns.resolveMx(domain).then(r => r.map(x => x.exchange)).catch(() => []),
    dns.resolveTxt(domain).then(r => r.map(t => t.join(''))).catch(() => []),
    dns.resolveNs(domain).catch(() => []),
  ]);
  return { a, mx, txt, ns };
}

export function checkSSL(domain) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect(443, domain, { servername: domain, timeout: 8000 }, () => {
      if (settled) return;
      settled = true;
      const cert = socket.getPeerCertificate();
      const now = new Date();
      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.round((validTo - now) / (1000 * 60 * 60 * 24));
      resolve({
        valid: socket.authorized || false,
        issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysRemaining,
        authorizationError: socket.authorizationError || null,
      });
      socket.end();
    });
    socket.on('error', (err) => { if (!settled) { settled = true; resolve({ valid: false, error: err.message }); } });
    socket.on('timeout', () => { if (!settled) { settled = true; socket.destroy(); resolve({ valid: false, error: 'Connection timed out' }); } });
  });
}

export async function checkSecurityHeaders(domain) {
  try {
    const res = await fetch(`https://${domain}`, { redirect: 'follow', signal: AbortSignal.timeout(8000) });
    const h = res.headers;
    return {
      reachable: true,
      status: res.status,
      server: h.get('server') || null,
      poweredBy: h.get('x-powered-by') || null,
      headers: {
        'Strict-Transport-Security': h.get('strict-transport-security'),
        'Content-Security-Policy': h.get('content-security-policy'),
        'X-Frame-Options': h.get('x-frame-options'),
        'X-Content-Type-Options': h.get('x-content-type-options'),
        'Referrer-Policy': h.get('referrer-policy'),
        'Permissions-Policy': h.get('permissions-policy'),
      },
    };
  } catch (err) {
    return { reachable: false, error: err.message };
  }
}

function checkPort(host, port, timeout = 2500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;
    socket.setTimeout(timeout);
    socket.on('connect', () => { resolved = true; socket.destroy(); resolve(true); });
    socket.on('timeout', () => { if (!resolved) { resolved = true; socket.destroy(); resolve(false); } });
    socket.on('error', () => { if (!resolved) { resolved = true; resolve(false); } });
    socket.connect(port, host);
  });
}

const COMMON_PORTS = { 21: 'FTP', 22: 'SSH', 25: 'SMTP', 3306: 'MySQL', 3389: 'RDP', 8080: 'HTTP-alt', 8443: 'HTTPS-alt' };

export async function checkCommonPorts(domain) {
  const entries = await Promise.all(
    Object.keys(COMMON_PORTS).map(async (port) => [port, await checkPort(domain, Number(port))])
  );
  return entries.reduce((acc, [port, open]) => {
    acc[port] = { open, service: COMMON_PORTS[port] };
    return acc;
  }, {});
}

function fingerprintNotes(headerCheck) {
  const notes = [];
  const server = (headerCheck.server || '').toLowerCase();
  const poweredBy = (headerCheck.poweredBy || '').toLowerCase();

  const PLATFORM_HOSTS = ['vercel', 'cloudflare', 'netlify', 'aws', 'github.com'];

  if (server.includes('nginx')) notes.push('Server header identifies as nginx. Confirm it is running a current, patched release.');
  else if (server.includes('apache')) notes.push('Server header identifies as Apache. Older 2.4.x releases have known CVEs — confirm the version is current.');
  else if (server && PLATFORM_HOSTS.some(p => server.includes(p))) notes.push(`Server header only reveals the hosting platform (${headerCheck.server}), not application-level details — good practice.`);
  else if (server) notes.push(`Server header reveals: ${headerCheck.server}. Consider whether this level of detail needs to be public.`);

  if (poweredBy.includes('php')) notes.push('X-Powered-By header exposes PHP details. Consider disabling this header (expose_php = Off) to reduce attacker reconnaissance.');

  if (!server && !poweredBy) notes.push('No technology fingerprint was exposed via response headers — this is good practice.');

  return notes;
}

export const HIGH_RISK_PORTS = ['21', '22', '3306', '3389'];

export function computeScore(scan) {
  let score = 100;
  const reasons = [];

  const headerEntries = Object.entries(scan.headers?.headers || {});
  const missingHeaders = headerEntries.filter(([, v]) => !v).map(([k]) => k);
  if (missingHeaders.length) {
    score -= missingHeaders.length * 5;
    reasons.push(`${missingHeaders.length} recommended security header(s) missing`);
  }

  if (!scan.ssl?.valid) {
    score -= 30;
    reasons.push('SSL certificate is invalid or could not be verified');
  } else if (scan.ssl.daysRemaining != null && scan.ssl.daysRemaining < 14) {
    score -= 10;
    reasons.push('SSL certificate expires in under 14 days');
  }

  for (const [port, info] of Object.entries(scan.ports || {})) {
    if (!info.open) continue;
    const penalty = HIGH_RISK_PORTS.includes(port) ? 15 : 5;
    score -= penalty;
    reasons.push(`Port ${port} (${info.service}) is open and reachable`);
  }

  score = Math.max(0, Math.min(100, score));
  const rating = score >= 85 ? 'LOW RISK' : score >= 60 ? 'MODERATE RISK' : 'HIGH RISK';

  return { score, rating, reasons };
}

// Reject raw IP literals, localhost, and private/link-local ranges.
// Blocks the most direct SSRF vectors where the buyer types e.g. 169.254.169.254
// (AWS metadata service) or 10.0.0.1 into the scanner, which would then be
// used as the target of real TCP/TLS/HTTP connections inside the Vercel Lambda.
const PRIVATE_IP_RE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|::1$|fc00:|fe80:)/;
const IP_LITERAL_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const LABEL_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

export function isSafeDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  if (domain.length > 253) return false;
  if (IP_LITERAL_RE.test(domain)) return false;       // raw IPv4 literal
  if (PRIVATE_IP_RE.test(domain)) return false;       // private/internal range
  if (domain.toLowerCase() === 'localhost') return false;

  const labels = domain.split('.');
  if (labels.length < 2) return false;                // must have at least a.tld

  const tld = labels[labels.length - 1];
  if (!/^[a-zA-Z]{2,}$/.test(tld)) return false;     // TLD must be all-alpha

  // Every label: 1–63 chars, alphanumeric + internal hyphens only
  return labels.every(label => label.length >= 1 && LABEL_RE.test(label));
}

export async function runScan(domain) {
  if (!isSafeDomain(domain)) {
    throw new Error(`Domain "${domain}" failed safety validation — will not scan`);
  }
  const [dnsResult, sslResult, headerResult, portResult] = await Promise.all([
    checkDNS(domain).catch(err => ({ error: err.message })),
    checkSSL(domain).catch(err => ({ valid: false, error: err.message })),
    checkSecurityHeaders(domain).catch(err => ({ reachable: false, error: err.message })),
    checkCommonPorts(domain).catch(() => ({})),
  ]);

  return {
    domain,
    scannedAt: new Date().toISOString(),
    dns: dnsResult,
    ssl: sslResult,
    headers: headerResult,
    ports: portResult,
    notes: fingerprintNotes(headerResult || {}),
  };
}
