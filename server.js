// TungWeb proxy server. Zero dependencies, needs Node 18+.
const http = require('http'), fs = require('fs'), path = require('path');
const dns = require('dns').promises, net = require('net'), { Readable } = require('stream');

const PORT = process.env.PORT || 3000;
const INDEX = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
const INJECT = '<script>' + fs.readFileSync(path.join(__dirname, 'inject.js'), 'utf8') + '</script>';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const DROP = new Set(['content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'content-encoding',
  'content-length', 'transfer-encoding', 'set-cookie', 'strict-transport-security', 'cross-origin-opener-policy',
  'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'connection', 'keep-alive', 'location', 'report-to', 'nel']);

// Block private/internal addresses so the proxy can't be used to reach your network (SSRF protection).
function priv(ip) {
  if (net.isIPv6(ip)) return ip === '::' || /^(::1$|f[cd]|fe80|::ffff:(127|10|192\.168|172\.(1[6-9]|2\d|3[01])|169\.254|0\.))/i.test(ip);
  const p = ip.split('.').map(Number);
  return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
}
async function safe(host) {
  if (process.env.ALLOW_PRIVATE) return true; // for local testing only
  host = host.replace(/^\[|\]$/g, '');
  try {
    if (net.isIP(host)) return !priv(host);
    return (await dns.lookup(host, { all: true })).every(a => !priv(a.address));
  } catch (e) { return false; }
}

const SKIP = /^(#|data:|blob:|javascript:|mailto:|tel:|about:)/i;
function rw(u, base, esc) {
  const raw = u.replace(/&amp;/g, '&').trim();
  if (!raw || SKIP.test(raw) || raw.startsWith('/p/')) return u;
  try {
    const a = new URL(raw, base);
    if (a.protocol !== 'http:' && a.protocol !== 'https:') return u;
    const o = '/p/' + a.href;
    return esc ? o.replace(/&/g, '&amp;').replace(/"/g, '%22').replace(/'/g, '%27') : o;
  } catch (e) { return u; }
}
function cssRw(css, base) {
  return css
    .replace(/url\(\s*(["']?)([^"')]+?)\1\s*\)/gi, (m, q, u) => 'url(' + q + rw(u, base, false) + q + ')')
    .replace(/@import\s+(["'])([^"']+)\1/gi, (m, q, u) => '@import ' + q + rw(u, base, false) + q);
}
function htmlRw(html, base) {
  const bm = html.match(/<base\b[^>]*\bhref\s*=\s*["']([^"']+)["']/i);
  if (bm) { try { base = new URL(bm[1], base).href; } catch (e) {} }
  html = html
    .replace(/<base\b[^>]*>/gi, '')
    .replace(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy[^>]*>/gi, '')
    .replace(/\s(?:integrity|nonce)\s*=\s*(["'])[\s\S]*?\1/gi, '')
    .replace(/\starget\s*=\s*(["'])_(?:top|parent)\1/gi, '')
    .replace(/(\s(?:src|href|action|poster|data-src)\s*=\s*)(["'])([\s\S]*?)\2/gi, (m, a, q, u) => a + q + rw(u, base, true) + q)
    .replace(/(\ssrcset\s*=\s*)(["'])([\s\S]*?)\2/gi, (m, a, q, v) => a + q + v.split(',').map(s => {
      s = s.trim(); const i = s.search(/\s/);
      return i < 0 ? rw(s, base, true) : rw(s.slice(0, i), base, true) + s.slice(i);
    }).join(', ') + q)
    .replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, a, c, b) => a + cssRw(c, base) + b);
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, m => m + INJECT) : INJECT + html;
}

function fail(res, code, msg) {
  res.writeHead(code, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<body style="font-family:sans-serif;background:#2c1b10;color:#f1dfc7;text-align:center;padding:60px"><h1>🪵 Tung hit a knot</h1><p>${msg}</p></body>`);
}

async function proxy(req, res, raw) {
  let target = raw.replace(/^(https?):\/+/i, '$1://');
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
  let U; try { U = new URL(target); } catch (e) { return fail(res, 400, 'That URL is not valid.'); }
  if (!(await safe(U.hostname))) return fail(res, 403, 'That address is blocked.');

  const h = { 'user-agent': UA, accept: req.headers.accept || '*/*', 'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9', referer: U.origin + '/' };
  if (req.headers.range) h.range = req.headers.range;
  if (req.headers['content-type']) h['content-type'] = req.headers['content-type'];
  let body;
  if (!['GET', 'HEAD'].includes(req.method)) {
    const c = []; for await (const x of req) c.push(x);
    body = Buffer.concat(c); h.origin = U.origin;
  }
  let r;
  try { r = await fetch(U.href, { method: req.method, headers: h, body, redirect: 'manual', signal: AbortSignal.timeout(25000) }); }
  catch (e) { return fail(res, 502, 'Could not reach ' + U.hostname + '.'); }

  const loc = r.headers.get('location');
  if (r.status >= 300 && r.status < 400 && loc) {
    let to; try { to = '/p/' + new URL(loc, U.href).href; } catch (e) { to = '/'; }
    res.writeHead(r.status, { location: to, 'access-control-allow-origin': '*' });
    return res.end();
  }
  const out = {};
  r.headers.forEach((v, k) => { if (!DROP.has(k)) out[k] = v; });
  out['access-control-allow-origin'] = '*';
  const ctype = r.headers.get('content-type') || '';

  if (/text\/html|application\/xhtml/i.test(ctype) && req.method !== 'HEAD') {
    const buf = Buffer.from(await r.arrayBuffer());
    const cs = /charset=["']?([\w-]+)/i.exec(ctype);
    let txt; try { txt = new TextDecoder(cs ? cs[1] : 'utf-8').decode(buf); } catch (e) { txt = buf.toString('utf8'); }
    out['content-type'] = 'text/html; charset=utf-8';
    res.writeHead(r.status, out);
    return res.end(htmlRw(txt, U.href));
  }
  if (/text\/css/i.test(ctype)) {
    out['content-type'] = 'text/css; charset=utf-8';
    res.writeHead(r.status, out);
    return res.end(cssRw(await r.text(), U.href));
  }
  res.writeHead(r.status, out);
  if (!r.body || req.method === 'HEAD') return res.end();
  const s = Readable.fromWeb(r.body);
  s.on('error', () => res.destroy());
  res.on('close', () => s.destroy());
  s.pipe(res);
}

http.createServer(async (req, res) => {
  try {
    const u = req.url;
    if (u === '/' || u === '/index.html') { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); return res.end(INDEX); }
    if (u === '/health') { res.writeHead(200); return res.end('ok'); }
    if (u.startsWith('/p/')) return await proxy(req, res, u.slice(3));
    // Root-relative requests made by proxied pages (e.g. "/style.css"): recover the site from the Referer.
    const m = (req.headers.referer || '').match(/\/p\/(https?:\/+[^\/?#]+)/i);
    if (m) { res.writeHead(307, { location: '/p/' + m[1].replace(/^(https?):\/+/i, '$1://') + u }); return res.end(); }
    res.writeHead(404); res.end('Not found');
  } catch (e) { if (!res.headersSent) fail(res, 500, 'Server error.'); else res.destroy(); }
}).listen(PORT, () => console.log('TungWeb running on http://localhost:' + PORT));
