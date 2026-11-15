import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHandler } from './handler.mjs';
import { Store } from './store.mjs';
import { createStealHandler } from '../../steal/src/turn.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const STORE_PATH = process.env.SEEN_STORE_PATH || path.resolve(here, '../data/seen.json');

if (!SECRET) {
  console.warn('[agent] WARNING: AGENT_GAMES_HMAC_SECRET not set — signature verification disabled (local dev only)');
}

const store = new Store(STORE_PATH);
const { handlePost } = createHandler({ secret: SECRET, store });

// Steal the VFY branch (integrated 2026-11-15): strategy config lives outside
// the agent folder and outside any repo — params + salt + registered
// commitment. If the file is absent the steal route stays disabled and
// gatekeeper traffic is unaffected.
const STEAL_CONFIG_PATH = path.resolve(here, '../../steal/strategy.local.json');
const STEAL_PAYLOAD_LOG = path.resolve(here, '../../steal-payloads.log');
let stealHandlePost = null;
try {
  const cfg = JSON.parse(fs.readFileSync(STEAL_CONFIG_PATH, 'utf8'));
  stealHandlePost = createStealHandler({
    secret: SECRET,
    params: cfg.params,
    salt: cfg.salt,
    commitmentHex: cfg.commitmentHex,
    log: console,
  }).handlePost;
  console.log('[agent] steal-the-vfy handler enabled');
} catch (err) {
  console.warn(`[agent] steal-the-vfy handler disabled (${err.message})`);
}

function isStealEnvelope(rawBody) {
  try {
    const parsed = JSON.parse(rawBody.toString('utf8'));
    return parsed && (parsed.eventId === 'steal-the-vfy' || (parsed.state && parsed.strategyCommitment));
  } catch { return false; }
}

const INTAKE_TOKEN_PATH = process.env.INTAKE_TOKEN_PATH || path.resolve(here, '../../intake-token.txt');
const AGENT_ENV_PATH = process.env.AGENT_ENV_PATH || path.resolve(here, '../../agent.env');
const INTAKE_FLAG_PATH = path.resolve(here, '../../secret-updated.flag');

function intakeToken() {
  try { return fs.readFileSync(INTAKE_TOKEN_PATH, 'utf8').trim(); } catch { return ''; }
}

function handleIntake(req, res) {
  const m = req.url.match(/^\/intake\/([a-z0-9]+)/);
  if (!m) return false;
  const token = intakeToken();
  if (!token || m[1] !== token) {
    res.writeHead(404, { 'content-type': 'text/html' });
    res.end('<h3>Link tidak valid atau sudah dipakai.</h3>');
    return true;
  }
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<!doctype html><meta charset="utf-8"><title>Agent Games secret intake</title>
<body style="font-family:sans-serif;max-width:520px;margin:40px auto;padding:0 16px">
<h3>Simpan HMAC secret Agent Games</h3>
<p>Paste secret dari dashboard Agent Games (yang muncul sekali saat agent dibuat / di-rotate), lalu klik Simpan. Secret langsung tersimpan ke server agent dan tidak ditampilkan lagi.</p>
<form method="POST">
<input name="secret" type="password" autocomplete="off" style="width:100%;padding:10px;font-size:16px" placeholder="paste secret di sini" required>
<button type="submit" style="margin-top:12px;padding:10px 20px;font-size:16px">Simpan</button>
</form></body>`);
    return true;
  }
  if (req.method === 'POST') {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size > 100_000) { req.destroy(); return; } chunks.push(c); });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let secret = '';
      try { secret = String(JSON.parse(raw).secret || ''); } catch {
        secret = new URLSearchParams(raw).get('secret') || '';
      }
      secret = secret.trim();
      if (secret.length < 16 || secret.length > 256 || /\s/.test(secret)) {
        res.writeHead(400, { 'content-type': 'text/html' });
        res.end('<h3>Secret tidak valid (panjang/karakter). Coba paste ulang.</h3>');
        return;
      }
      fs.writeFileSync(AGENT_ENV_PATH, `AGENT_GAMES_HMAC_SECRET=${secret}\n`, { mode: 0o600 });
      fs.writeFileSync(INTAKE_FLAG_PATH, new Date().toISOString());
      try { fs.unlinkSync(INTAKE_TOKEN_PATH); } catch {}
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<h3>Secret tersimpan ✓</h3><p>Kamu bisa tutup tab ini dan kembali ke dashboard Agent Games.</p>');
      console.log('[agent] intake: new HMAC secret stored, restarting to load it');
      setTimeout(() => process.exit(0), 700);
    });
    return true;
  }
  return false;
}

const server = http.createServer((req, res) => {
  if (handleIntake(req, res)) return;
  if (req.method === 'GET') {
    const body = JSON.stringify({ ok: true, service: 'proof-gatekeeper', protocolVersion: 'v1' });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'method not allowed' }));
    return;
  }
  const chunks = [];
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size > 1_000_000) { req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', async () => {
    const rawBody = Buffer.concat(chunks);
    const started = Date.now();
    try {
      let out;
      if (stealHandlePost && isStealEnvelope(rawBody)) {
        // Keep the raw platform payload — the first practice turn is the
        // ground truth for the remaining protocol questions (FINDINGS §7).
        try { fs.appendFileSync(STEAL_PAYLOAD_LOG, `\n===== ${new Date().toISOString()} =====\n` + rawBody.toString('utf8')); } catch {}
        out = await stealHandlePost(rawBody, req.headers['x-agent-games-signature']);
      } else {
        out = await handlePost(rawBody, req.headers['x-agent-games-signature']);
      }
      res.writeHead(out.status, out.headers);
      res.end(out.body);
      console.log(`[agent] POST ${req.url} -> ${out.status} in ${Date.now() - started}ms`);
    } catch (err) {
      console.error('[agent] handler error:', err);
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal error' }));
    }
  });
});

server.listen(PORT, () => console.log(`[agent] proof-gatekeeper listening on :${PORT}`));
