const path = require('path');
const crypto = require('crypto');
const express = require('express');

const app = express();
const PORT = process.env.PORT || 4000;
const PIXI_URL = process.env.PIXI_URL || 'http://localhost:3000';

// Demo only: in-memory store (lost on restart)
const OAUTH_CLIENT = {
  id: 'printify-demo',
  redirectUri: 'http://localhost:4000/callback',
};
const pendingAuth = new Map(); // state -> code_verifier

app.use(express.urlencoded({ extended: false }));

function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${esc(title)}</title>
  <style>
    body { margin: 0; min-height: 100vh; font-family: system-ui, sans-serif; background: #f3f4f6; color: #111827; }
    main { padding: 2rem; max-width: 960px; margin: 0 auto; }
    p { color: #4b5563; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1rem; margin-top: 1.5rem; }
    .picture { background: #fff; border-radius: 12px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08); padding: 1rem; cursor: pointer; display: flex; flex-direction: column; gap: 0.5rem; border: 3px solid transparent; }
    .picture:has(input:checked) { border-color: #2563eb; }
    .picture input { align-self: flex-end; }
    .picture img { width: 100%; border-radius: 8px; }
    .picture span { font-weight: 600; }
  </style>
</head>
<body>
  <main>${body}</main>
</body>
</html>`;
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.post('/connect', (req, res) => {
  const state = crypto.randomBytes(16).toString('base64url');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  pendingAuth.set(state, codeVerifier);

  const authorizeUrl = new URL('/authorize', PIXI_URL);
  authorizeUrl.search = new URLSearchParams({
    client_id: OAUTH_CLIENT.id,
    redirect_uri: OAUTH_CLIENT.redirectUri,
    scope: 'pictures.read',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  }).toString();
  res.redirect(authorizeUrl.toString());
});

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) {
    return res.status(400).send(page('Authorization failed', `<p>Pixi returned: ${esc(error)}</p>`));
  }

  const codeVerifier = pendingAuth.get(state);
  pendingAuth.delete(state); // single-use
  if (!code || !codeVerifier) {
    return res.status(400).send(page('Authorization failed', '<p>Unknown or expired state.</p>'));
  }

  try {
    const tokenRes = await fetch(`${PIXI_URL}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: OAUTH_CLIENT.id,
        grant_type: 'authorization_code',
        authorization_code: code,
        code_verifier: codeVerifier,
      }),
    });
    const token = await tokenRes.json();
    if (!tokenRes.ok) {
      return res.status(400).send(page('Authorization failed', `<p>Token exchange failed: ${esc(token.error)}</p>`));
    }

    const picturesRes = await fetch(`${PIXI_URL}/api/pictures`, {
      headers: { Authorization: `Bearer ${token.access_token}` },
    });
    const picturesBody = await picturesRes.json();
    if (!picturesRes.ok) {
      return res.status(502).send(page('Could not load pictures', `<p>Pixi returned: ${esc(picturesBody.error)}</p>`));
    }
    const { user, pictures } = picturesBody;

    const cards = pictures
      .map((p) => `
      <label class="picture">
        <input type="checkbox" name="picture" value="${esc(p.id)}">
        <img src="${esc(PIXI_URL)}${esc(p.url)}" alt="${esc(p.title)}">
        <span>${esc(p.title)}</span>
      </label>`)
      .join('');

    res.send(page('Select pictures', `
      <h1>Select pictures to print</h1>
      <p>Connected to Pixi as ${esc(user)}. Selected: <span id="count">0</span></p>
      <div class="grid">${cards}</div>
      <script>
        const update = () => {
          document.getElementById('count').textContent = document.querySelectorAll('input[name="picture"]:checked').length;
        };
        document.querySelectorAll('input[name="picture"]').forEach((box) => box.addEventListener('change', update));
      </script>`));
  } catch (err) {
    res.status(502).send(page('Could not reach Pixi', `<p>${esc(err.message)}</p>`));
  }
});

app.listen(PORT, () => {
  console.log(`Printify running at http://localhost:${PORT}`);
});
