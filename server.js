const express = require('express');
const http = require('http');
const path = require('path');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.set('trust proxy', 1);
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ===== MAIL =====
const MAIL_USER = process.env.MAIL_USER || 'vantoriumdeveloper@gmail.com';
const MAIL_PASS = process.env.MAIL_PASS || 'tiuc ofld nhsz irbu';

const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: MAIL_USER, pass: MAIL_PASS },
  connectionTimeout: 10000, // 10sn içinde bağlan
  greetingTimeout: 10000,
  socketTimeout: 15000
});

mailer.verify().then(
  () => console.log('[MAIL] SMTP bağlantısı OK'),
  (e) => console.error('[MAIL] SMTP HATA:', e.message)
);

async function sendVerifyMail(to, code) {
  return mailer.sendMail({
    from: `"Vantorium" <${MAIL_USER}>`,
    to,
    subject: 'Vantorium — Doğrulama Kodun',
    html: `
      <div style="font-family:Inter,Arial,sans-serif;max-width:480px;margin:auto;padding:32px;background:#111318;color:#e9edf3;border-radius:12px">
        <h2 style="margin:0 0 12px;font-size:20px">Doğrulama Kodun</h2>
        <p style="color:#9aa3b2;font-size:14px;margin:0 0 20px">Kod 5 dakika geçerli.</p>
        <div style="font-size:32px;font-weight:700;letter-spacing:8px;padding:18px;background:#171a21;border:1px dashed #2e3542;border-radius:10px;text-align:center;color:#3b82f6">${code}</div>
        <p style="color:#5f6878;font-size:12px;margin-top:20px">Bu kodu kimseyle paylaşma.</p>
      </div>
    `
  });
}

// ===== RATE LIMITS =====
app.use(rateLimit({
  windowMs: 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ underAttack: true, error: 'UNDER ATTACK — yavaşla' })
}));

const authLimiter = rateLimit({
  windowMs: 60 * 1000, max: 10,
  handler: (req, res) => res.status(429).json({ error: 'Çok fazla deneme. 1 dakika bekle.' })
});

const sendLimiter = rateLimit({
  windowMs: 60 * 1000, max: 3,
  keyGenerator: (req) => req.body?.email?.toLowerCase() || req.ip,
  handler: (req, res) => res.status(429).json({ error: 'Çok fazla kod talebi. 1 dakika bekle.' })
});

// ===== DB =====
const users = {};
const sessions = {};
const pendingRegistrations = {};
const companies = {};
let uid = 1;

const newToken = () => crypto.randomBytes(32).toString('hex');
const newCode = () => Math.floor(100000 + Math.random() * 900000).toString();
const newRegId = () => 'r' + crypto.randomBytes(8).toString('hex');

// ===== SLIDER CAPTCHA =====
const sliderChallenges = {}; // cid -> { target, expires }

app.post('/api/bot/challenge', (req, res) => {
  const cid = crypto.randomBytes(8).toString('hex');
  // Hedef pozisyon (0-100 arası), tam turda 100'e eşit olmalı
  const target = 50 + Math.floor(Math.random() * 50); // 50-99
  sliderChallenges[cid] = { target, expires: Date.now() + 2 * 60 * 1000 };
  for (const k in sliderChallenges) if (sliderChallenges[k].expires < Date.now()) delete sliderChallenges[k];
  res.json({ cid, target });
});

app.post('/api/bot/solve', (req, res) => {
  const { cid, value } = req.body || {};
  const c = sliderChallenges[cid];
  if (!c) return res.status(400).json({ error: 'Challenge geçersiz' });
  if (Date.now() > c.expires) { delete sliderChallenges[cid]; return res.status(400).json({ error: 'Süre doldu' }); }
  // value 0-100 arası tam sayı olmalı, hedefin ±3 toleransında
  const v = Math.round(Number(value));
  if (isNaN(v) || v < 0 || v > 100) return res.status(400).json({ error: 'Geçersiz değer' });
  if (Math.abs(v - c.target) > 3) return res.status(400).json({ error: 'Yanlış hizalama, tekrar dene' });
  delete sliderChallenges[cid];
  res.json({ ok: true });
});

// ===== AUTH MIDDLEWARE =====
function auth(req, res, next) {
  const token = req.cookies?.vtoken;
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Giriş yapmalısın' });
  req.userId = sessions[token];
  req.user = users[req.userId];
  if (!req.user) return res.status(401).json({ error: 'Oturum geçersiz' });
  next();
}
function verifyGuard(req, res, next) {
  if (!req.user.verified) return res.status(403).json({ error: 'Doğrulama tamamlanmadı' });
  next();
}

// ===== REGISTER =====
app.post('/api/register/send-code', authLimiter, sendLimiter, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Eksik alan' });
  if (name.trim().length < 2) return res.status(400).json({ error: 'İsim çok kısa' });
  if (password.length < 6) return res.status(400).json({ error: 'Şifre en az 6 karakter' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Geçersiz e-posta' });
  if (Object.values(users).some(u => u.email === email.toLowerCase()))
    return res.status(400).json({ error: 'Bu e-posta zaten kayıtlı' });

  const passHash = await bcrypt.hash(password, 10);
  const code = newCode();
  const regId = newRegId();
  pendingRegistrations[regId] = {
    name: name.trim(), email: email.toLowerCase(), passHash,
    code, expires: Date.now() + 5 * 60 * 1000, attempts: 0
  };

  console.log('[REG] Kod gönderilecek:', email);
  try {
    const info = await sendVerifyMail(email, code);
    console.log('[MAIL] OK:', email, info.messageId);
  } catch (e) {
    console.error('[MAIL] HATA:', e.message);
    delete pendingRegistrations[regId];
    return res.status(500).json({ error: 'Mail gönderilemedi. Railway env (MAIL_USER/MAIL_PASS) veya Gmail app password kontrol et.' });
  }
  res.json({ ok: true, regId });
});

app.post('/api/register/confirm', authLimiter, async (req, res) => {
  const { regId, code } = req.body || {};
  const p = pendingRegistrations[regId];
  if (!p) return res.status(400).json({ error: 'Kayıt bulunamadı' });
  if (Date.now() > p.expires) { delete pendingRegistrations[regId]; return res.status(400).json({ error: 'Kod süresi doldu' }); }
  p.attempts++;
  if (p.attempts > 5) { delete pendingRegistrations[regId]; return res.status(400).json({ error: 'Çok fazla deneme. Tekrar başla.' }); }
  if (p.code !== String(code)) return res.status(400).json({ error: 'Kod yanlış' });

  const id = 'u' + (uid++);
  users[id] = { id, name: p.name, email: p.email, passHash: p.passHash, verified: true, createdAt: Date.now() };
  delete pendingRegistrations[regId];

  const token = newToken();
  sessions[token] = id;
  res.cookie('vtoken', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 });
  res.json({ ok: true, user: { id, name: p.name, verified: true } });
});

app.post('/api/register/resend', authLimiter, sendLimiter, async (req, res) => {
  const { regId } = req.body || {};
  const p = pendingRegistrations[regId];
  if (!p) return res.status(400).json({ error: 'Kayıt bulunamadı' });
  const code = newCode();
  p.code = code;
  p.expires = Date.now() + 5 * 60 * 1000;
  p.attempts = 0;
  try {
    await sendVerifyMail(p.email, code);
  } catch (e) {
    console.error('[MAIL] HATA:', e.message);
    return res.status(500).json({ error: 'Mail gönderilemedi' });
  }
  res.json({ ok: true });
});

// ===== LOGIN =====
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Eksik alan' });
  const user = Object.values(users).find(u => u.email === email.toLowerCase());
  if (!user) return res.status(400).json({ error: 'E-posta veya şifre hatalı' });
  const ok = await bcrypt.compare(password, user.passHash);
  if (!ok) return res.status(400).json({ error: 'E-posta veya şifre hatalı' });

  const token = newToken();
  sessions[token] = user.id;
  res.cookie('vtoken', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 });
  res.json({ ok: true, user: { id: user.id, name: user.name, verified: user.verified } });
});

app.post('/api/logout', (req, res) => {
  const t = req.cookies?.vtoken;
  if (t) delete sessions[t];
  res.clearCookie('vtoken');
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ id: req.user.id, name: req.user.name, email: req.user.email, verified: req.user.verified });
});

// ===== COMPANIES =====
app.get('/api/companies', auth, verifyGuard, (req, res) => {
  res.json(Object.values(companies).map(c => ({
    id: c.id, name: c.name, owner: c.owner, members: c.members,
    shares: c.shares, chat: c.chat.slice(-50),
    joinRequests: c.owner === req.userId ? c.joinRequests : []
  })));
});

app.post('/api/company/create', auth, verifyGuard, (req, res) => {
  const { name } = req.body || {};
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Ad gerekli' });
  const id = 'c' + Date.now();
  companies[id] = {
    id, name: name.trim(), owner: req.userId, members: [req.userId],
    shares: { [req.userId]: 100 }, chat: [], joinRequests: []
  };
  res.json({ ok: true, company: companies[id] });
});

app.post('/api/attack', auth, verifyGuard, (req, res) => {
  const { companyId } = req.body || {};
  const c = companies[companyId];
  if (!c) return res.status(404).json({ error: 'Şirket yok' });
  if (c.owner === req.userId) return res.status(400).json({ error: 'Kendi şirketin' });
  if (c.members.includes(req.userId)) return res.status(400).json({ error: 'Zaten üyesin' });

  const success = Math.random() < 0.05;
  if (success) {
    const s = c.shares[c.owner] || 0;
    c.shares[req.userId] = (c.shares[req.userId] || 0) + s;
    c.shares[c.owner] = 0;
    c.owner = req.userId;
    if (!c.members.includes(req.userId)) c.members.push(req.userId);
    res.json({ success: true });
  } else res.json({ success: false });
});

app.post('/api/company/join', auth, verifyGuard, (req, res) => {
  const { companyId } = req.body || {};
  const c = companies[companyId];
  if (!c) return res.status(404).json({ error: 'yok' });
  if (c.members.includes(req.userId)) return res.status(400).json({ error: 'Zaten üyesin' });
  if (!c.joinRequests.includes(req.userId)) c.joinRequests.push(req.userId);
  io.to(c.owner).emit('join-request', { companyId, name: req.user.name });
  res.json({ ok: true });
});

app.post('/api/company/join/respond', auth, verifyGuard, (req, res) => {
  const { companyId, userId, accept } = req.body || {};
  const c = companies[companyId];
  if (!c || c.owner !== req.userId) return res.status(403).json({ error: 'yetki yok' });
  c.joinRequests = c.joinRequests.filter(x => x !== userId);
  if (accept) { c.members.push(userId); c.shares[userId] = 0; }
  io.to(userId).emit('join-response', { companyId, accepted: !!accept });
  res.json({ ok: true });
});

// ===== SOCKET =====
const chatFlood = {};
io.on('connection', (socket) => {
  const token = socket.handshake.auth?.token;
  if (!token || !sessions[token]) return socket.disconnect();
  const userId = sessions[token];
  const user = users[userId];
  if (!user || !user.verified) return socket.disconnect();
  socket.join(userId);

  socket.on('join-company-room', (cid) => {
    const c = companies[cid];
    if (c && c.members.includes(userId)) socket.join('c:' + cid);
  });

  socket.on('chat-message', ({ companyId, text }) => {
    const c = companies[companyId];
    if (!c || !c.members.includes(userId)) return;
    if (typeof text !== 'string') return;
    text = text.trim().slice(0, 300);
    if (!text) return;

    const now = Date.now(), key = userId + ':' + companyId;
    chatFlood[key] = (chatFlood[key] || []).filter(t => now - t < 10000);
    if (chatFlood[key].length > 5) return socket.emit('chat-error', { msg: 'Anti-Flood: yavaşla' });
    chatFlood[key].push(now);

    const last = c.chat[c.chat.length - 1];
    if (last && last.text === text && last.userId === userId) return;

    const msg = { userId, name: user.name, text, t: now };
    c.chat.push(msg);
    if (c.chat.length > 200) c.chat.shift();
    io.to('c:' + companyId).emit('chat-message', msg);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Vantorium:', PORT));
