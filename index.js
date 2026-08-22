const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const JSZip = require('jszip');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT) || 10000;
const COOKIE_NAME = 'web2zip_session';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret-in-production';
const LOGIN_EMAIL = process.env.DEMO_EMAIL || 'admin@example.com';
const LOGIN_PASSWORD = process.env.DEMO_PASSWORD || 'ChangeMe123!';

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function b64url(value) {
    return Buffer.from(value).toString('base64url');
}

function sign(value) {
    return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function createSession(payload) {
    const body = b64url(JSON.stringify({ ...payload, exp: Date.now() + 24 * 60 * 60 * 1000 }));
    return `${body}.${sign(body)}`;
}

function readSession(req) {
    const header = req.headers.cookie || '';
    const match = header.split(';').map(v => v.trim()).find(v => v.startsWith(`${COOKIE_NAME}=`));
    if (!match) return null;
    const token = decodeURIComponent(match.slice(COOKIE_NAME.length + 1));
    const [body, signature] = token.split('.');
    if (!body || !signature || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(sign(body)))) return null;
    try {
        const data = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        return data.exp > Date.now() ? data : null;
    } catch (_) {
        return null;
    }
}

function setSession(res, payload) {
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(createSession(payload))}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
}

function clearSession(res) {
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
}

function requireAuth(req, res, next) {
    if (readSession(req)) return next();
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Authentication required.' });
    return res.redirect('/login');
}

function safeRedirect(value) {
    return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') ? value : '/';
}

app.get('/login', (req, res) => {
    if (readSession(req)) return res.redirect('/');
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (email !== LOGIN_EMAIL.toLowerCase() || password !== LOGIN_PASSWORD) {
        return res.status(401).json({ error: 'Invalid email or password.' });
    }
    setSession(res, { email, provider: 'password' });
    res.json({ ok: true, redirect: safeRedirect(req.body.redirect || '/') });
});

app.post('/api/logout', (req, res) => {
    clearSession(res);
    res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
    const session = readSession(req);
    res.json(session ? { authenticated: true, email: session.email, provider: session.provider } : { authenticated: false });
});

// Optional OAuth endpoints. Configure the matching environment variables to enable them.
function oauthConfig(provider) {
    if (provider === 'google') return {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
        token: 'https://oauth2.googleapis.com/token',
        user: 'https://openidconnect.googleapis.com/v1/userinfo',
        scope: 'openid email profile'
    };
    if (provider === 'github') return {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        authorize: 'https://github.com/login/oauth/authorize',
        token: 'https://github.com/login/oauth/access_token',
        user: 'https://api.github.com/user',
        scope: 'read:user user:email'
    };
}

function baseUrl(req) {
    if (process.env.APP_URL) return process.env.APP_URL.replace(/\/$/, '');
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    return `${proto}://${req.get('host')}`;
}

app.get('/auth/:provider', (req, res) => {
    const provider = req.params.provider;
    const cfg = oauthConfig(provider);
    if (!cfg || !cfg.clientId || !cfg.clientSecret) {
        return res.status(503).send(`${provider} login is not configured. Add the required environment variables.`);
    }
    const state = crypto.randomBytes(24).toString('hex');
    const redirectUri = `${baseUrl(req)}/auth/${provider}/callback`;
    const params = new URLSearchParams({ client_id: cfg.clientId, redirect_uri: redirectUri, response_type: 'code', scope: cfg.scope, state });
    res.setHeader('Set-Cookie', `oauth_state=${state}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
    res.redirect(`${cfg.authorize}?${params.toString()}`);
});

app.get('/auth/:provider/callback', async (req, res) => {
    const provider = req.params.provider;
    const cfg = oauthConfig(provider);
    const cookies = Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(v => v.trim().split('=')));
    if (!cfg || !cfg.clientId || !cfg.clientSecret || !req.query.code || cookies.oauth_state !== req.query.state) return res.status(400).send('OAuth authentication failed.');
    try {
        const redirectUri = `${baseUrl(req)}/auth/${provider}/callback`;
        const tokenResponse = await axios.post(cfg.token, new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, code: req.query.code, redirect_uri: redirectUri }), { headers: { Accept: 'application/json' } });
        const accessToken = tokenResponse.data.access_token;
        if (!accessToken) throw new Error('No access token returned.');
        const userResponse = await axios.get(cfg.user, { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json', 'User-Agent': 'Web2Zip' } });
        const email = userResponse.data.email || `${userResponse.data.login || userResponse.data.name || provider}@oauth.local`;
        setSession(res, { email, provider });
        res.setHeader('Set-Cookie', `oauth_state=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
        res.redirect('/');
    } catch (error) {
        console.error('OAuth error:', error.response?.data || error.message);
        res.status(500).send('OAuth login failed. Check your provider credentials and callback URL.');
    }
});

app.get('/', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/proxy', requireAuth, async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).send('URL missing');
    try {
        const response = await axios.get(targetUrl, {
            responseType: 'arraybuffer',
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36', Accept: '*/*' },
            timeout: 15000,
            validateStatus: () => true
        });
        res.setHeader('Content-Type', response.headers['content-type'] || 'application/octet-stream');
        res.status(response.status).send(response.data);
    } catch (error) {
        res.status(500).send(`Proxy Error: ${error.message}`);
    }
});

app.get('/api/convert', requireAuth, async (req, res) => {
    let targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).json({ error: 'URL MISSED!' });
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;
    let urlObj;
    try { urlObj = new URL(targetUrl); } catch (_) { return res.status(400).json({ error: 'Invalid URL.' }); }

    const zip = new JSZip();
    const zipName = urlObj.hostname.replace(/^www\./, '').replace(/\./g, '_') + '.zip';
    const assets = [];
    const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
    try {
        const response = await axios.get(targetUrl, { headers: { 'User-Agent': userAgent }, timeout: 15000 });
        const $ = cheerio.load(response.data);
        $('base').remove();
        const processAsset = (tag, attr, folder) => {
            $(tag).each((i, el) => {
                const src = $(el).attr(attr);
                if (src && !src.startsWith('data:') && !src.startsWith('#')) {
                    try {
                        const assetUrl = new URL(src, targetUrl).href;
                        const fileName = `file-${i}.${folder}`;
                        assets.push({ url: assetUrl, path: `${folder}/${fileName}` });
                        $(el).attr(attr, `./${folder}/${fileName}`);
                    } catch (_) {}
                }
            });
        };
        processAsset('link[rel="stylesheet"]', 'href', 'css');
        processAsset('script[src]', 'src', 'js');
        processAsset('img', 'src', 'img');
        zip.file('index.html', $.html());
        for (const asset of assets) {
            try {
                const assetResponse = await axios.get(asset.url, { responseType: 'arraybuffer', timeout: 5000, headers: { 'User-Agent': userAgent } });
                zip.file(asset.path, assetResponse.data);
            } catch (_) {}
        }
        const content = await zip.generateAsync({ type: 'nodebuffer' });
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);
        res.send(content);
    } catch (error) {
        res.status(500).json({ error: 'Server extraction failed.', details: error.message });
    }
});

// Health check for Render/Vercel monitoring.
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

// Render needs the process to listen on 0.0.0.0:$PORT. Vercel imports the app as a serverless function.
if (!process.env.VERCEL) {
    app.listen(PORT, '0.0.0.0', () => console.log(`Web2Zip running on 0.0.0.0:${PORT}`));
}

module.exports = app;

