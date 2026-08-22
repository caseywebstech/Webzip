const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const JSZip = require('jszip');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT) || 10000;
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/proxy', async (req, res) => {
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

app.get('/api/convert', async (req, res) => {
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
