// api/auth.js
// Vercel serverless function — handles GitHub OAuth for Decap CMS
// ----------------------------------------------------------------
// SETUP:
// 1. Go to github.com/settings/developers → OAuth Apps → New OAuth App
//    Homepage URL:      https://www.cyber-node.com
//    Callback URL:      https://www.cyber-node.com/api/auth
// 2. Copy Client ID and Client Secret
// 3. In Vercel dashboard → your project → Settings → Environment Variables:
//    GITHUB_CLIENT_ID     = your client id
//    GITHUB_CLIENT_SECRET = your client secret
// ----------------------------------------------------------------

import { randomBytes } from 'crypto';

const GITHUB_CLIENT_ID     = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const ORIGIN               = 'https://www.cyber-node.com';
const STATE_COOKIE         = 'cn_oauth_state';

// JSON.stringify doesn't escape `<`, so a value containing "</script>"
// could break out of the inline <script> block below — escape it first.
function safeJsonForScript(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

export default async function handler(req, res) {
  const { code, state } = req.query;

  // Step 1 — Redirect to GitHub OAuth, pinning a random state in a cookie
  // so step 2 can verify the callback wasn't forged (CSRF on the OAuth flow).
  if (!code) {
    const csrfState = randomBytes(16).toString('hex');
    res.setHeader('Set-Cookie', `${STATE_COOKIE}=${csrfState}; Path=/api/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=600`);

    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      scope: 'repo,user',
      state: csrfState,
    });
    return res.redirect(`https://github.com/login/oauth/authorize?${params}`);
  }

  // Step 2 — Verify state against the cookie set in step 1, then exchange code for token
  const cookies = parseCookies(req.headers.cookie);
  const expectedState = cookies[STATE_COOKIE];
  res.setHeader('Set-Cookie', `${STATE_COOKIE}=; Path=/api/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);

  if (!expectedState || expectedState !== state) {
    return res.status(400).send('Invalid OAuth state — possible CSRF attempt. Please restart the login.');
  }

  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        client_id:     GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
      }),
    });

    const tokenData = await tokenRes.json();

    if (tokenData.error) {
      return res.status(400).send(`
        <script>
          window.opener.postMessage(
            'authorization:github:error:${safeJsonForScript(tokenData.error)}',
            '${ORIGIN}'
          );
          window.close();
        </script>
      `);
    }

    // Step 3 — Send token back to CMS popup window
    return res.send(`
      <script>
        window.opener.postMessage(
          'authorization:github:success:${safeJsonForScript({ token: tokenData.access_token, provider: 'github' })}',
          '${ORIGIN}'
        );
        window.close();
      </script>
    `);

  } catch (err) {
    return res.status(500).send(`OAuth error: ${err.message}`);
  }
}
