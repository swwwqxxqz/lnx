// ╔══════════════════════════════════════════════════════════╗
// ║  LUNEX · Real-Time Chat Server                            ║
// ║  Node.js + Express + Socket.io + SQLite                   ║
// ╚══════════════════════════════════════════════════════════╝
require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

// ── Config ────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-' + Math.random().toString(36);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'lunex.db');

// ── Database setup ────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    topic TEXT DEFAULT '',
    category TEXT DEFAULT 'General',
    admin_only INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id TEXT NOT NULL,
    author TEXT NOT NULL,
    text TEXT NOT NULL,
    action INTEGER DEFAULT 0,
    ts INTEGER NOT NULL,
    FOREIGN KEY(channel_id) REFERENCES channels(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_msg_channel ON messages(channel_id, ts);
  CREATE TABLE IF NOT EXISTS dms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pair_key TEXT NOT NULL,
    author TEXT NOT NULL,
    text TEXT NOT NULL,
    encrypted INTEGER DEFAULT 0,
    ts INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_dm_pair ON dms(pair_key, ts);
`);

// Migration: add `category` column if missing (for upgrades)
try { db.exec(`ALTER TABLE channels ADD COLUMN category TEXT DEFAULT 'General'`); } catch (e) { /* already exists */ }

// Seed default channels
const seedChannels = [
  { id: 'general', name: 'general', topic: 'General discussion', category: 'Text Channels', admin_only: 0 },
  { id: 'lunex',   name: 'lunex',   topic: 'About Lunex',         category: 'Text Channels', admin_only: 0 },
  { id: 'random',  name: 'random',  topic: 'Random stuff',         category: 'Community',     admin_only: 0 },
  { id: 'help',    name: 'help',    topic: 'Need help?',           category: 'Community',     admin_only: 0 },
  { id: 'admin-chat', name: 'admin-chat', topic: 'Admin only',     category: 'Admin',         admin_only: 1 }
];
const insertCh = db.prepare('INSERT OR IGNORE INTO channels (id, name, topic, category, admin_only, created_at) VALUES (?, ?, ?, ?, ?, ?)');
seedChannels.forEach(c => insertCh.run(c.id, c.name, c.topic, c.category, c.admin_only, Date.now()));

// ── Express app ───────────────────────────────────────────
const app = express();
const server = http.createServer(app);

app.use(helmet({ contentSecurityPolicy: false })); // CSP off so Socket.io client + inline scripts work
app.use(cors());
app.use(express.json({ limit: '64kb' }));
app.use(express.static(__dirname)); // serve all html/js/css from project root

// ── Helpers ───────────────────────────────────────────────
function pairKey(a, b) { return [a, b].sort().join(':'); }
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
}
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
function sanitize(text, max) {
  if (typeof text !== 'string') return null;
  text = text.trim();
  if (!text || text.length > (max || 2000)) return null;
  // Block obvious XSS payloads (defense in depth — frontend also escapes)
  const bad = /<\s*script|javascript:|<\s*iframe|on\w+\s*=/i;
  if (bad.test(text)) return null;
  return text;
}
function validUsername(u) {
  return typeof u === 'string' && /^[A-Za-z0-9_]{3,32}$/.test(u);
}

// ── Rate limiters ─────────────────────────────────────────
const authLimiter   = rateLimit({ windowMs: 60_000, max: 10, standardHeaders: true });
const writeLimiter  = rateLimit({ windowMs: 10_000, max: 30, standardHeaders: true });

// ╔══════════════════════════════════════════════════════════╗
// ║  REST API                                                 ║
// ╚══════════════════════════════════════════════════════════╝

// ── Register ──────────────────────────────────────────────
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: 'Invalid username (3-32 alphanumeric/_)' });
  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (typeof password !== 'string' || password.length < 6 || password.length > 200) return res.status(400).json({ error: 'Password 6-200 chars' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
  if (existing) return res.status(409).json({ error: 'Username or email already taken' });

  const hash = await bcrypt.hash(password, 10);
  const role = (db.prepare('SELECT COUNT(*) as c FROM users').get().c === 0) ? 'superadmin' : 'member';
  const info = db.prepare('INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)').run(username, email, hash, role, Date.now());
  const user = { id: info.lastInsertRowid, username, role };
  res.json({ token: signToken(user), user });
});

// ── Login ─────────────────────────────────────────────────
app.post('/api/login', authLimiter, async (req, res) => {
  const { ident, password } = req.body || {};
  if (typeof ident !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Invalid input' });
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(ident, ident);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.role === 'banned') return res.status(403).json({ error: 'Account banned' });
  res.json({ token: signToken(user), user: { id: user.id, username: user.username, role: user.role } });
});

// ── Me ────────────────────────────────────────────────────
app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, username, email, role, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(user);
});

// ── Users (list) ──────────────────────────────────────────
app.get('/api/users', authMiddleware, (req, res) => {
  const users = db.prepare('SELECT id, username, email, role, created_at FROM users ORDER BY username').all();
  // Map for compatibility with admin UI
  const mapped = users.map(u => ({ ...u, joined: new Date(u.created_at).toLocaleDateString() }));
  res.json(mapped);
});

// ── Channels ──────────────────────────────────────────────
app.get('/api/channels', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM channels ORDER BY created_at').all());
});

app.post('/api/channels', authMiddleware, (req, res) => {
  if (req.user.role !== 'superadmin' && req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { name, topic, admin_only, category } = req.body || {};
  const cleanName = sanitize(name, 32);
  if (!cleanName) return res.status(400).json({ error: 'Invalid channel name' });
  const id = 'ch_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
  db.prepare('INSERT INTO channels (id, name, topic, category, admin_only, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, cleanName, sanitize(topic, 200) || '', sanitize(category, 32) || 'General', admin_only ? 1 : 0, Date.now());
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(id);
  io.emit('channel:created', ch);
  res.json(ch);
});

// Edit channel
app.patch('/api/channels/:id', authMiddleware, (req, res) => {
  if (req.user.role !== 'superadmin' && req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const ch = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!ch) return res.status(404).json({ error: 'Not found' });
  const name = sanitize(req.body.name, 32) || ch.name;
  const topic = sanitize(req.body.topic, 200) || '';
  const category = sanitize(req.body.category, 32) || ch.category || 'General';
  const admin_only = req.body.admin_only ? 1 : 0;
  db.prepare('UPDATE channels SET name=?, topic=?, category=?, admin_only=? WHERE id=?').run(name, topic, category, admin_only, ch.id);
  const updated = db.prepare('SELECT * FROM channels WHERE id = ?').get(ch.id);
  io.emit('channel:updated', updated);
  res.json(updated);
});

// Delete channel
app.delete('/api/channels/:id', authMiddleware, (req, res) => {
  if (req.user.role !== 'superadmin' && req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.prepare('DELETE FROM messages WHERE channel_id = ?').run(req.params.id);
  db.prepare('DELETE FROM channels WHERE id = ?').run(req.params.id);
  io.emit('channel:deleted', req.params.id);
  res.json({ ok: true });
});

// DM partners list
app.get('/api/dm-partners', authMiddleware, (req, res) => {
  const me = req.user.username;
  const rows = db.prepare(`
    SELECT pair_key, MAX(ts) as last_ts, (
      SELECT text FROM dms d2 WHERE d2.pair_key = dms.pair_key ORDER BY ts DESC LIMIT 1
    ) as last_text, (
      SELECT encrypted FROM dms d3 WHERE d3.pair_key = dms.pair_key ORDER BY ts DESC LIMIT 1
    ) as last_encrypted
    FROM dms WHERE pair_key LIKE ? OR pair_key LIKE ?
    GROUP BY pair_key ORDER BY last_ts DESC
  `).all(me + ':%', '%:' + me);
  const partners = rows.map(r => {
    const [a, b] = r.pair_key.split(':');
    return { partner: a === me ? b : a, last_ts: r.last_ts, last_text: r.last_text, last_encrypted: r.last_encrypted };
  });
  res.json(partners);
});

// ── Message history ───────────────────────────────────────
app.get('/api/messages/:channelId', authMiddleware, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const msgs = db.prepare('SELECT * FROM messages WHERE channel_id = ? ORDER BY ts DESC LIMIT ?').all(req.params.channelId, limit);
  res.json(msgs.reverse());
});

app.get('/api/dms/:partner', authMiddleware, (req, res) => {
  if (!validUsername(req.params.partner)) return res.status(400).json({ error: 'Invalid partner' });
  const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
  const key = pairKey(req.user.username, req.params.partner);
  const msgs = db.prepare('SELECT * FROM dms WHERE pair_key = ? ORDER BY ts DESC LIMIT ?').all(key, limit);
  res.json(msgs.reverse());
});

// ── Admin: change role / ban ──────────────────────────────
app.post('/api/admin/role', authMiddleware, writeLimiter, (req, res) => {
  if (req.user.role !== 'superadmin' && req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { username, role } = req.body || {};
  const allowed = ['superadmin','admin','moderator','vip','member','banned'];
  if (!validUsername(username) || !allowed.includes(role)) return res.status(400).json({ error: 'Bad input' });
  if (req.user.role !== 'superadmin' && role === 'superadmin') return res.status(403).json({ error: 'Only superadmin can grant superadmin' });
  db.prepare('UPDATE users SET role = ? WHERE username = ?').run(role, username);
  io.emit('user:role-changed', { username, role });
  res.json({ ok: true });
});

// ── Health ────────────────────────────────────────────────
app.get('/api/health', (_req, res) => res.json({ ok: true, time: Date.now() }));

// ╔══════════════════════════════════════════════════════════╗
// ║  Socket.io — real-time                                    ║
// ╚══════════════════════════════════════════════════════════╝
const io = new Server(server, { cors: { origin: '*' } });

// Auth middleware for sockets
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    next(new Error('Invalid token'));
  }
});

// In-memory presence + rate limit
const onlineUsers = new Map(); // username -> Set<socketId>
const sendBuckets = new Map(); // username -> [timestamps]
function checkRate(username, max = 8, windowMs = 5000) {
  const now = Date.now();
  let arr = sendBuckets.get(username) || [];
  arr = arr.filter(t => now - t < windowMs);
  if (arr.length >= max) return false;
  arr.push(now);
  sendBuckets.set(username, arr);
  return true;
}

io.on('connection', (socket) => {
  const { username, role } = socket.user;
  if (role === 'banned') { socket.emit('error', 'banned'); return socket.disconnect(true); }

  // Track presence
  if (!onlineUsers.has(username)) onlineUsers.set(username, new Set());
  onlineUsers.get(username).add(socket.id);
  io.emit('presence:online', Array.from(onlineUsers.keys()));

  // Join personal room (for DMs)
  socket.join('user:' + username);

  // ── Channel join ────────────────────────────────────────
  socket.on('channel:join', (channelId) => {
    if (typeof channelId !== 'string' || channelId.length > 64) return;
    socket.join('ch:' + channelId);
  });
  socket.on('channel:leave', (channelId) => {
    if (typeof channelId !== 'string') return;
    socket.leave('ch:' + channelId);
  });

  // ── Send message to channel ─────────────────────────────
  socket.on('message:send', (payload, ack) => {
    try {
      const { channelId, text, action } = payload || {};
      if (!checkRate(username)) return ack && ack({ error: 'Rate limit' });
      const clean = sanitize(text, 2000);
      if (!clean) return ack && ack({ error: 'Invalid message' });
      const channel = db.prepare('SELECT * FROM channels WHERE id = ?').get(channelId);
      if (!channel) return ack && ack({ error: 'Channel not found' });
      if (channel.admin_only && role !== 'superadmin' && role !== 'admin') return ack && ack({ error: 'Admin-only channel' });

      const ts = Date.now();
      const info = db.prepare('INSERT INTO messages (channel_id, author, text, action, ts) VALUES (?, ?, ?, ?, ?)')
        .run(channelId, username, clean, action ? 1 : 0, ts);
      const msg = { id: info.lastInsertRowid, channel_id: channelId, author: username, text: clean, action: action ? 1 : 0, ts };
      io.to('ch:' + channelId).emit('message:new', msg);
      ack && ack({ ok: true, msg });
    } catch (e) {
      ack && ack({ error: e.message });
    }
  });

  // ── Typing indicator ────────────────────────────────────
  socket.on('typing', ({ channelId }) => {
    if (typeof channelId !== 'string') return;
    socket.to('ch:' + channelId).emit('typing', { username, channelId });
  });

  // ── DM send ─────────────────────────────────────────────
  socket.on('dm:send', (payload, ack) => {
    try {
      const { to, text, encrypted } = payload || {};
      if (!validUsername(to)) return ack && ack({ error: 'Invalid recipient' });
      if (!checkRate(username)) return ack && ack({ error: 'Rate limit' });
      // Allow encrypted blobs to be longer; sanitize raw text
      const clean = encrypted ? (typeof text === 'string' && text.length < 50000 ? text : null) : sanitize(text, 2000);
      if (!clean) return ack && ack({ error: 'Invalid message' });
      const ts = Date.now();
      const key = pairKey(username, to);
      const info = db.prepare('INSERT INTO dms (pair_key, author, text, encrypted, ts) VALUES (?, ?, ?, ?, ?)')
        .run(key, username, clean, encrypted ? 1 : 0, ts);
      const msg = { id: info.lastInsertRowid, pair_key: key, author: username, text: clean, encrypted: encrypted ? 1 : 0, ts };
      io.to('user:' + to).emit('dm:new', msg);
      io.to('user:' + username).emit('dm:new', msg);
      ack && ack({ ok: true, msg });
    } catch (e) {
      ack && ack({ error: e.message });
    }
  });

  socket.on('dm:typing', ({ to }) => {
    if (!validUsername(to)) return;
    socket.to('user:' + to).emit('dm:typing', { from: username });
  });

  // ── Disconnect ──────────────────────────────────────────
  socket.on('disconnect', () => {
    const set = onlineUsers.get(username);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) onlineUsers.delete(username);
    }
    io.emit('presence:online', Array.from(onlineUsers.keys()));
  });
});

// ── Start ─────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n┌─────────────────────────────────────────────┐`);
  console.log(`│  Lunex server running on port ${PORT}          │`);
  console.log(`│  http://localhost:${PORT}                       │`);
  console.log(`│  Database: ${DB_PATH}`);
  console.log(`└─────────────────────────────────────────────┘\n`);
});
