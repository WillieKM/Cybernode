const RESEND_API_URL = 'https://api.resend.com/emails';

export async function sendReportEmail({ to, domain, pdfBuffer, from, replyTo }) {
  const res = await fetch(RESEND_API_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: from || `Cyber-Node <${process.env.RESEND_FROM || 'reports@cyber-node.com'}>`,
      to,
      reply_to: replyTo || process.env.RESEND_REPLY_TO || undefined,
      subject: `Your Cyber-Node Security Report — ${domain}`,
      text: `Hi,\n\nYour full security report for ${domain} is attached as a PDF.\n\nQuestions? Just reply to this email.\n\n— Cyber-Node`,
      attachments: [
        { filename: `cyber-node-report-${domain}.pdf`, content: pdfBuffer.toString('base64') },
      ],
    }),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(`Resend error (${res.status}): ${data.message || JSON.stringify(data)}`);
  }
  return data;
}
