const path = require('path');
const crypto = require('crypto');
const express = require('express');

const app = express();
const PORT = process.env.PORT || 4000;
const PIXI_URL = process.env.PIXI_URL || 'http://localhost:3000';

const OAUTH_CLIENT = {
  id: 'printify-demo',
  redirectUri: 'http://localhost:4000/callback',
};

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.post('/connect', (req, res) => {
  const state = crypto.randomBytes(16).toString('base64url');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  res.cookie('pkce', `${state}.${codeVerifier}`, { sameSite: 'lax', path: '/callback', maxAge: 10 * 60 * 1000 });

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

app.get('/config.js', (req, res) => {
  res.type('js').send(`window.PRINTIFY_CONFIG = ${JSON.stringify({ pixiUrl: PIXI_URL, clientId: OAUTH_CLIENT.id })};`);
});

app.get('/callback', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'callback.html'));
});

app.listen(PORT, () => {
  console.log(`Printify running at http://localhost:${PORT}`);
});
