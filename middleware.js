// Gates /admin behind a shared username/password before the Decap CMS
// bundle or config.yml are even served. This does NOT replace GitHub
// OAuth — Decap still needs "Login with GitHub" underneath to actually
// commit posts. This just keeps random visitors from reaching that
// screen at all. Credentials come from Vercel env vars, not hardcoded.
export const config = {
  matcher: ['/admin', '/admin/:path*'],
};

export default function middleware(request) {
  const expectedUser = process.env.ADMIN_GATE_USER;
  const expectedPass = process.env.ADMIN_GATE_PASSWORD;

  const authHeader = request.headers.get('authorization');

  if (authHeader && authHeader.startsWith('Basic ')) {
    const decoded = atob(authHeader.slice(6));
    const sep = decoded.indexOf(':');
    const user = decoded.slice(0, sep);
    const pass = decoded.slice(sep + 1);

    if (user === expectedUser && pass === expectedPass) {
      return; // credentials match — let the request through
    }
  }

  return new Response('Authentication required', {
    status: 401,
    headers: { 'WWW-Authenticate': 'Basic realm="Cyber-Node Admin"' },
  });
}
