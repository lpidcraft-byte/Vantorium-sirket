const express = require('express');
const http = require('http');
const path = require('path');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Anti-DDoS / Under Attack limiter
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ underAttack: true, msg: 'UNDER ATTACK - Rate limit aşıldı' });
  }
});
app.use(globalLimiter);

// ====== IN-MEMORY DB ======
const users = {};     // id -> {name, verified, shares, deeded, tapu}
const companies = {}; // id -> {name, owner, members:[], shares:[], chat:[], joinRequests:[]}
let uid = 1;

function newUser(name) {
  const id = 'u' + (uid++);
  users[id] = { id, name: name || ('Kullanıcı' + uid), verified: false, shares: {}, taps: [] };
  return users[id];
}

// ====== API ======
app.post('/api/verify', (req, res) => {
  const { name } = req.body;
  const u = newUser(name);
  u.verified = true;
  res.json({ ok: true, user: u });
});

app.get('/api/companies', (req, res) => {
  res.json(Object.values(companies));
});

app.post('/api/company/create', (req, res) => {
  const { userId, name } = req.body;
  if (!users[userId]) return res.status(400).json({ error: 'no user' });
  const id = 'c' + Date.now();
  companies[id] = {
    id, name: name || 'Yeni Şirket',
    owner: userId, members: [userId],
    shares: { [userId]: 100 },
    chat: [], joinRequests: []
  };
  res.json({ ok: true, company: companies[id] });
});

// Saldırı (5% başarı)
app.post('/api/attack', (req, res) => {
  const { userId, companyId } = req.body;
  const c = companies[companyId];
  if (!c) return res.status(404).json({ error: 'yok' });
  if (c.owner === userId) return res.status(400).json({ error: 'sahipsin' });

  const success = Math.random() < 0.05;
  if (success) {
    // Hisseleri ele geçir
    const ownerShares = c.shares[c.owner] || 0;
    c.shares[userId] = (c.shares[userId] || 0) + ownerShares;
    c.shares[c.owner] = 0;
    c.owner = userId;
    if (!c.members.includes(userId)) c.members.push(userId);
    res.json({ success: true, msg: 'Pass Found!' });
  } else {
    res.json({ success: false, msg: 'Pass not found' });
  }
});

// Katılma isteği
app.post('/api/company/join', (req, res) => {
  const { userId, companyId } = req.body;
  const c = companies[companyId];
  if (!c) return res.status(404).json({ error: 'yok' });
  if (c.members.includes(userId)) return res.json({ ok: false, msg: 'Zaten üyesin' });
  if (!c.joinRequests.includes(userId)) c.joinRequests.push(userId);
  io.to(c.owner).emit('join-request', { companyId, userId, name: users[userId]?.name });
  res.json({ ok: true });
});

app.post('/api/company/join/respond', (req, res) => {
  const { ownerId, companyId, userId, accept } = req.body;
  const c = companies[companyId];
  if (!c || c.owner !== ownerId) return res.status(403).json({ error: 'yetki' });
  c.joinRequests = c.joinRequests.filter(x => x !== userId);
  if (accept) {
    c.members.push(userId);
    c.shares[userId] = 0;
    io.to(userId).emit('join-response', { companyId, accepted: true });
  } else {
    io.to(userId).emit('join-response', { companyId, accepted: false });
  }
  res.json({ ok: true });
});

// Soğuk hisse / tapu transferi (örnek)
app.post('/api/transfer', (req, res) => {
  const { from, to, companyId, amount } = req.body;
  const c = companies[companyId];
  if (!c) return res.status(404).json({ error: 'yok' });
  if ((c.shares[from] || 0) < amount) return res.status(400).json({ error: 'yetersiz' });
  c.shares[from] -= amount;
  c.shares[to] = (c.shares[to] || 0) + amount;
  res.json({ ok: true });
});

// ====== SOCKET.IO (Sohbet + Bildirim) ======
const chatFlood = {};
io.on('connection', (socket) => {
  socket.on('join-user', (uid) => { socket.join(uid); });

  socket.on('join-company-room', (companyId) => {
    socket.join('c:' + companyId);
  });

  socket.on('chat-message', ({ companyId, userId, name, text }) => {
    const c = companies[companyId];
    if (!c || !c.members.includes(userId)) return;

    // Anti flood
    const now = Date.now();
    const key = userId + ':' + companyId;
    if (!chatFlood[key]) chatFlood[key] = [];
    chatFlood[key] = chatFlood[key].filter(t => now - t < 10000);
    if (chatFlood[key].length > 5) {
      socket.emit('chat-error', { msg: 'Anti-Flood: çok hızlı yazıyorsun' });
      return;
    }
    chatFlood[key].push(now);

    // Anti spam
    const last = c.chat[c.chat.length - 1];
    if (last && last.text === text && last.userId === userId) return;
    if (text.length > 300) text = text.slice(0, 300);

    const msg = { userId, name, text, t: now };
    c.chat.push(msg);
    if (c.chat.length > 200) c.chat.shift();
    io.to('c:' + companyId).emit('chat-message', msg);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Vantorium çalışıyor:', PORT));
