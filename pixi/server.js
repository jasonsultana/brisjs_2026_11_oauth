const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const AUTH_COOKIE = 'auth';
const JWT_SECRET = 'pixi-demo-signing-secret';

// Demo only: single mock user and in-memory sessions (lost on restart)
const MOCK_USER = { username: 'demo', password: 'demo1234' };
const sessions = new Map(); // token -> username

const OAUTH_CLIENT = {
  id: 'printify-demo',
  redirectUris: ['http://localhost:4000/callback'],
};
const authCodes = new Map(); // code -> { username, clientId, redirectUri, scope, codeChallenge }

const PICTURES = [
  { id: 1, title: '1993 Mazda RX-7 (FD)', year: 1993, url: '/images/rx7.jpg' },
  { id: 2, title: '1994 Toyota Supra (A80)', year: 1994, url: '/images/supra.jpg' },
  { id: 3, title: '1992 Honda NSX (NA1)', year: 1992, url: '/images/nsx.jpg' },
  { id: 4, title: '1991 Nissan Skyline GT-R (R32)', year: 1991, url: '/images/skyline.jpg' },
  { id: 5, title: '1995 Honda Integra Type R (DC2)', year: 1995, url: '/images/integra.jpg' },
];

const CORS_ORIGINS = ['http://localhost:4000'];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (CORS_ORIGINS.includes(origin)) {
    res.set({
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    });
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use('/images', express.static(path.join(__dirname, 'public', 'images')));

function currentUser(req) {
  const token = req.cookies[AUTH_COOKIE];
  return token ? sessions.get(token) : undefined;
}

function startSession(res, username) {
  const token = crypto.randomUUID();
  sessions.set(token, username);
  res.cookie(AUTH_COOKIE, token, { httpOnly: true, sameSite: 'lax' });
}

function isValidAuthRequest({ client_id, redirect_uri }) {
  return client_id === OAUTH_CLIENT.id && OAUTH_CLIENT.redirectUris.includes(redirect_uri);
}

app.get('/', (req, res) => {
  if (!currentUser(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/login', (req, res) => {
  if (currentUser(req)) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username !== MOCK_USER.username || password !== MOCK_USER.password) {
    return res.redirect('/login?error=invalid');
  }

  startSession(res, username);
  res.redirect('/');
});

app.get('/authorize', (req, res) => {
  if (!isValidAuthRequest(req.query)) {
    return res.status(400).send('Invalid client_id or redirect_uri');
  }
  res.sendFile(path.join(__dirname, 'views', 'authorize.html'));
});

app.post('/authorize', (req, res) => {
  if (!isValidAuthRequest(req.query)) {
    return res.status(400).send('Invalid client_id or redirect_uri');
  }

  const { username, password } = req.body;
  if (username !== MOCK_USER.username || password !== MOCK_USER.password) {
    return res.redirect(`/authorize?${new URLSearchParams({ ...req.query, error: 'invalid' })}`);
  }

  const { client_id, redirect_uri, scope, state, code_challenge } = req.query;
  const code = crypto.randomUUID();
  authCodes.set(code, { username, clientId: client_id, redirectUri: redirect_uri, scope, codeChallenge: code_challenge });

  const callback = new URL(redirect_uri);
  callback.searchParams.set('code', code);
  if (state) callback.searchParams.set('state', state);

  startSession(res, username);
  res.redirect(callback.toString());
});

app.post('/oauth/token', (req, res) => {
  const { client_id, authorization_code, grant_type, code_verifier } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  if (client_id !== OAUTH_CLIENT.id) {
    return res.status(400).json({ error: 'invalid_client' });
  }

  const authCode = authCodes.get(authorization_code);
  authCodes.delete(authorization_code); // single-use
  if (!authCode || authCode.clientId !== client_id) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  const verifierHash = crypto.createHash('sha256').update(code_verifier ?? '').digest('base64url');
  if (!code_verifier || verifierHash !== authCode.codeChallenge) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  const access_token = jwt.sign(
    { sub: authCode.username, client_id, scope: authCode.scope },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
  res.json({ access_token, token_type: 'Bearer', expires_in: 3600, scope: authCode.scope });
});

app.get('/pictures', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Not authorized' });

  res.json({ user, pictures: PICTURES });
});

app.get('/api/pictures', (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer /, '');
  try {
    const claims = jwt.verify(token, JWT_SECRET);
    res.json({ user: claims.sub, pictures: PICTURES });
  } catch {
    res.status(401).json({ error: 'invalid_token' });
  }
});

app.listen(PORT, () => {
  console.log(`Pixi running at http://localhost:${PORT}`);
});
