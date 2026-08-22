const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const JSZip = require('jszip');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-in-render';
const sessions = new Map();

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function sign(value) {
    return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');
}
function makeToken(user) {
    const payload = Buffer.from(JSON.stringify({ user, exp: Date.now() + 24 * 60 * 60 * 1000 })).toString('base64url');
    return `${payload}.${sign(payload)}`;
}
function readToken(token) {
    try {
        const [payload, signature] = token.split('.');
        if (!payload || !signature || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(sign(payload)))) return null;
        const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
        if (data.exp < Date.now()) return null;
        return data;
    } catch (_) { return null; }
}
function auth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const session = readToken(token);
    if (!session) return res.status(401).json({ error: 'LOGIN_REQUIRED' });
    req.user = session.user;
    next();
}

// Demo email authentication. For production, replace with a real database/provider.
const DEMO_USERS = new Map([
    [process.env.DEMO_EMAIL || 'admin@example.com', process.env.DEMO_PASSWORD || 'ChangeMe123!']
]);

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/api/login', (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!email || !password) return res.status(400).json({ error: 'EMAIL_AND_PASSWORD_REQUIRED' });
    const expected = DEMO_USERS.get(email);
    if (!expected || password !== expected) return res.status(401).json({ error: 'INVALID_LOGIN' });
    res.json({ token: makeToken(email), email });
});

app.get('/api/oauth/:provider', (req, res) => {
    // OAuth requires your own Google/GitHub OAuth credentials and callback URLs.
    const provider = String(req.params.provider).toLowerCase();
    if (!['google', 'github'].includes(provider)) return res.status(400).json({ error: 'UNSUPPORTED_PROVIDER' });
    res.status(501).json({ error: 'OAUTH_NOT_CONFIGURED', message: `Configure ${provider} OAuth credentials before enabling this button.` });
});

app.get('/api/me', auth, (req, res) => res.json({ authenticated: true, email: req.user }));

app.get('/api/proxy', auth, async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).send('URL missing');
    try {
        const response = await axios.get(targetUrl, {
            responseType: 'arraybuffer',
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36', Accept: '*/*' },
            timeout: 15000,
            validateStatus: () => true
        });
        res.setHeader('Content-Type', response.headers['content-type'] || 'application/octet-stream');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.status(response.status).send(response.data);
    } catch (error) { res.status(500).send(`Proxy Error: ${error.message}`); }
});

app.get('/api/convert', auth, async (req, res) => {
    let targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).json({ error: 'URL MISSED!' });
    if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;

    const zip = new JSZip();
    let urlObj;
    try { urlObj = new URL(targetUrl); } catch (_) { return res.status(400).json({ error: 'INVALID_URL' }); }
    const zipName = urlObj.hostname.replace('www.', '').replace(/\./g, '_') + '.zip';
    const assets = [];
    const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36';

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
                const r = await axios.get(asset.url, { responseType: 'arraybuffer', timeout: 5000, headers: { 'User-Agent': userAgent } });
                zip.file(asset.path, r.data);
            } catch (_) {}
        }
        const content = await zip.generateAsync({ type: 'nodebuffer' });
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);
        res.send(content);
    } catch (error) { res.status(500).json({ error: 'Server extraction failed.', details: error.message }); }
});

app.listen(PORT, '0.0.0.0', () => console.log(`Web2Zip online on port ${PORT}`));
