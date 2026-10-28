const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const AUTH_COOKIE = 'auth';

// Demo only: single mock user and in-memory sessions (lost on restart)
const MOCK_USER = { username: 'demo', password: 'demo1234' };
const sessions = new Map(); // token -> username

const OAUTH_CLIENT = {
  id: 'printify-demo',
  redirectUris: ['http://localhost:4000/callback'],
};
const authCodes = new Map(); // code -> { username, clientId, redirectUri, scope, codeChallenge }

const PICTURES = [
  { id: 1, title: '1993 Mazda RX-7 (FD)', year: 1993, url: '/images/rx7.svg' },
  { id: 2, title: '1994 Toyota Supra (A80)', year: 1994, url: '/images/supra.svg' },
  { id: 3, title: '1992 Honda NSX (NA1)', year: 1992, url: '/images/nsx.svg' },
  { id: 4, title: '1991 Nissan Skyline GT-R (R32)', year: 1991, url: '/images/skyline.svg' },
  { id: 5, title: '1995 Honda Integra Type R (DC2)', year: 1995, url: '/images/integra.svg' },
];

app.use(express.urlencoded({ extended: false }));
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

app.get('/pictures', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Not authorized' });

  res.json({ user, pictures: PICTURES });
});

app.listen(PORT, () => {
  console.log(`Pixi running at http://localhost:${PORT}`);
});
