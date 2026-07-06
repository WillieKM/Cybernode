import PDFDocument from 'pdfkit';
import { computeScore, HIGH_RISK_PORTS } from './scan-domain.js';

const COLORS = {
  accent: '#0e1f38',
  blue: '#0099cc',
  green: '#0a9b6c',
  red: '#d6334c',
  orange: '#c97a18',
  text: '#1a1a1a',
  muted: '#666666',
  border: '#dddddd',
};

function ratingColor(rating) {
  if (rating === 'LOW RISK') return COLORS.green;
  if (rating === 'MODERATE RISK') return COLORS.orange;
  return COLORS.red;
}

function sectionHeader(doc, title) {
  doc.moveDown(1);
  doc.fontSize(13).fillColor(COLORS.accent).font('Helvetica-Bold').text(title);
  doc.moveTo(doc.x, doc.y + 2).lineTo(doc.page.width - doc.page.margins.right, doc.y + 2)
    .strokeColor(COLORS.border).lineWidth(1).stroke();
  doc.moveDown(0.5);
  doc.font('Helvetica').fillColor(COLORS.text).fontSize(10);
}

function kvRow(doc, label, value, valueColor) {
  const startX = doc.x;
  doc.font('Helvetica-Bold').fillColor(COLORS.muted).fontSize(9).text(label, startX, doc.y, { continued: true, width: 160 });
  doc.font('Helvetica').fillColor(valueColor || COLORS.text).fontSize(9).text('  ' + value);
}

function buildRecommendations(scan, score) {
  const recs = [];
  const h = scan.headers?.headers || {};
  if (!h['Strict-Transport-Security']) recs.push('Add a Strict-Transport-Security header to force HTTPS on all future visits.');
  if (!h['Content-Security-Policy']) recs.push('Add a Content-Security-Policy header to reduce the impact of any future XSS vulnerability.');
  if (!h['X-Frame-Options']) recs.push('Add X-Frame-Options (or CSP frame-ancestors) to prevent clickjacking.');
  if (!h['X-Content-Type-Options']) recs.push('Add X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks.');
  if (!h['Referrer-Policy']) recs.push('Add a Referrer-Policy header to control what leaks to external sites via the Referer header.');

  if (!scan.ssl?.valid) recs.push('Fix the SSL/TLS certificate immediately — visitors may see browser security warnings.');
  else if (scan.ssl.daysRemaining != null && scan.ssl.daysRemaining < 14) recs.push(`Renew the SSL certificate — it expires in ${scan.ssl.daysRemaining} day(s).`);

  for (const [port, info] of Object.entries(scan.ports || {})) {
    if (info.open) recs.push(`Review whether port ${port} (${info.service}) needs to be publicly reachable — close it if not required.`);
  }

  if (!recs.length) recs.push('No critical issues found in this automated check. Keep monitoring as your stack evolves.');
  return recs;
}

const SERVICES = {
  riskAssessment: { name: 'Risk Assessment', price: 'From $3,500', desc: 'A full vulnerability scan, security posture evaluation, and a prioritized remediation roadmap for the issues found above.' },
  pentest: { name: 'Penetration Testing', price: '$7.5K–$15K avg', desc: 'Hands-on exploitation testing of exposed services and open ports, with an executive-level report.' },
  monitoring: { name: 'Managed Monitoring', price: '$500–$2K/mo', desc: 'Continuous threat detection to keep this clean posture intact as your infrastructure evolves.' },
  compliance: { name: 'Compliance Consulting', price: 'Custom quote', desc: 'HIPAA / NIST / SOC2 readiness support if these gaps need to be closed for an audit or certification.' },
};

function buildServiceRecommendations(scan, score) {
  const picks = [];
  const hasOpenHighRiskPort = Object.entries(scan.ports || {}).some(([port, info]) => info.open && HIGH_RISK_PORTS.includes(port));
  const missingHeaderCount = Object.values(scan.headers?.headers || {}).filter(v => !v).length;

  if (score.rating === 'HIGH RISK' || missingHeaderCount >= 3 || !scan.ssl?.valid) {
    picks.push(SERVICES.riskAssessment);
  }
  if (hasOpenHighRiskPort) {
    picks.push(SERVICES.pentest);
  }
  if (score.rating === 'LOW RISK' && !picks.length) {
    picks.push(SERVICES.monitoring);
  }
  if (!picks.length) {
    picks.push(SERVICES.riskAssessment);
  }
  return picks;
}

export function generateReportPDF(scan) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margins: { top: 50, bottom: 50, left: 56, right: 56 } });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const score = computeScore(scan);
    const scanDate = new Date(scan.scannedAt).toLocaleString('en-US', { dateStyle: 'long', timeStyle: 'short' });

    // Header band
    doc.rect(0, 0, doc.page.width, 90).fill(COLORS.accent);
    doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(20).text('CYBER-NODE', 56, 32);
    doc.font('Helvetica').fontSize(11).fillColor('#9fd6ff').text('Full Security Report', 56, 58);
    doc.fontSize(9).fillColor('#9fd6ff').text(scanDate, 0, 36, { align: 'right', width: doc.page.width - 56 });

    doc.fillColor(COLORS.text).fontSize(11);
    doc.y = 115;

    // Summary box
    const boxY = doc.y;
    doc.rect(56, boxY, doc.page.width - 112, 80).fillAndStroke('#f5f7fa', COLORS.border);
    doc.fillColor(COLORS.muted).font('Helvetica').fontSize(9).text('TARGET DOMAIN', 70, boxY + 14);
    doc.fillColor(COLORS.text).font('Helvetica-Bold').fontSize(16).text(scan.domain, 70, boxY + 28);

    doc.fillColor(COLORS.muted).font('Helvetica').fontSize(9).text('SECURITY SCORE', 320, boxY + 14);
    doc.fillColor(ratingColor(score.rating)).font('Helvetica-Bold').fontSize(24).text(`${score.score}/100`, 320, boxY + 26);
    doc.fillColor(ratingColor(score.rating)).font('Helvetica-Bold').fontSize(10).text(score.rating, 320, boxY + 54);

    doc.y = boxY + 96;
    doc.x = 56;

    // SSL/TLS
    sectionHeader(doc, 'SSL / TLS Certificate');
    if (scan.ssl?.valid) {
      kvRow(doc, 'Status', 'Valid', COLORS.green); doc.moveDown(0.3);
      kvRow(doc, 'Issuer', scan.ssl.issuer || 'Unknown'); doc.moveDown(0.3);
      kvRow(doc, 'Expires', `${scan.ssl.validTo} (${scan.ssl.daysRemaining} days remaining)`,
        scan.ssl.daysRemaining < 14 ? COLORS.red : COLORS.text);
    } else {
      kvRow(doc, 'Status', `Invalid or unreachable — ${scan.ssl?.error || scan.ssl?.authorizationError || 'unknown error'}`, COLORS.red);
    }

    // DNS
    sectionHeader(doc, 'DNS Records');
    kvRow(doc, 'A Records', (scan.dns?.a || []).join(', ') || 'None found'); doc.moveDown(0.3);
    kvRow(doc, 'Nameservers', (scan.dns?.ns || []).join(', ') || 'None found'); doc.moveDown(0.3);
    kvRow(doc, 'Mail (MX)', (scan.dns?.mx || []).filter(Boolean).join(', ') || 'None found'); doc.moveDown(0.3);
    kvRow(doc, 'SPF Record', (scan.dns?.txt || []).find(t => t.startsWith('v=spf1')) || 'Not found');

    // Security Headers
    sectionHeader(doc, 'HTTP Security Headers');
    const headerList = Object.entries(scan.headers?.headers || {});
    if (!headerList.length) {
      doc.fillColor(COLORS.red).text('Site was not reachable over HTTPS — headers could not be checked.');
    } else {
      headerList.forEach(([name, value]) => {
        kvRow(doc, name, value ? 'Present' : 'Missing', value ? COLORS.green : COLORS.red);
        doc.moveDown(0.3);
      });
    }

    // Open Ports
    sectionHeader(doc, 'Common Port Exposure');
    const portList = Object.entries(scan.ports || {});
    if (!portList.length) {
      doc.fillColor(COLORS.muted).text('Port check did not complete.');
    } else {
      portList.forEach(([port, info]) => {
        kvRow(doc, `Port ${port} (${info.service})`, info.open ? 'OPEN' : 'Closed', info.open ? COLORS.red : COLORS.green);
        doc.moveDown(0.3);
      });
    }

    // Tech notes
    if (scan.notes?.length) {
      sectionHeader(doc, 'Technology & Hardening Notes');
      scan.notes.forEach(note => { doc.text(`•  ${note}`); doc.moveDown(0.2); });
    }

    // Recommendations
    sectionHeader(doc, 'Recommended Actions');
    buildRecommendations(scan, score).forEach(rec => {
      doc.fillColor(COLORS.text).text(`•  ${rec}`);
      doc.moveDown(0.2);
    });

    // How Cyber-Node can help
    sectionHeader(doc, 'How Cyber-Node Can Help');
    buildServiceRecommendations(scan, score).forEach(svc => {
      doc.font('Helvetica-Bold').fillColor(COLORS.accent).fontSize(10).text(svc.name, { continued: true });
      doc.font('Helvetica').fillColor(COLORS.muted).fontSize(9).text(`   ${svc.price}`);
      doc.font('Helvetica').fillColor(COLORS.text).fontSize(9).text(svc.desc);
      doc.moveDown(0.5);
    });
    doc.font('Helvetica-Bold').fillColor(COLORS.blue).fontSize(9)
      .text('Reply to this email or reach us at sales@cyber-node.com to get started.');

    // Footer disclaimer
    doc.moveDown(1.5);
    doc.fontSize(8).fillColor(COLORS.muted).font('Helvetica-Oblique').text(
      'This report is generated from automated, non-intrusive checks (DNS, TLS, HTTP response headers, and common port reachability). ' +
      'It is not a substitute for a full manual penetration test. Questions? Reply to this email or contact sales@cyber-node.com.',
      { width: doc.page.width - 112 }
    );

    doc.end();
  });
}
