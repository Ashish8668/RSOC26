require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3002);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-this-secret-immediately-123456';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const db = new Database(path.join(__dirname, 'safe_demo.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    phone TEXT,
    balance REAL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    item TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    address TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

seedIfNeeded();

app.use(helmet());
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed by CORS policy'));
  },
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, try again later.' },
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, try again in 15 minutes.' },
});

app.use(globalLimiter);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', server: 'safe-api', port: PORT });
});

app.get('/api', (_req, res) => {
  res.json({
    name: 'ShopEasy API (Safe)',
    version: '2.0.0',
    security: ['helmet', 'rate-limit', 'rbac', 'ownership-checks', 'parameterized-sql'],
    endpoints: [
      'POST /api/auth/login',
      'GET /api/users/:id',
      'GET /api/admin/users',
      'GET /api/products?q=',
      'GET /api/orders/:id',
    ],
  });
});

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const user = db.prepare('SELECT id, email, role, password_hash FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: JWT_EXPIRES_IN }
  );

  res.json({
    message: 'Login successful',
    token,
    user: { id: user.id, email: user.email, role: user.role },
  });
});

app.get('/api/users', authenticateToken, (req, res) => {
  if (req.user.role === 'admin') {
    const users = db.prepare('SELECT id, name, email, role, phone, balance, created_at FROM users ORDER BY id').all();
    return res.json(users);
  }
  const user = db.prepare('SELECT id, name, email, role, phone, balance, created_at FROM users WHERE id = ?').get(req.user.id);
  return res.json(user ? [user] : []);
});

app.get('/api/users/:id', authenticateToken, (req, res) => {
  const requestedId = Number(req.params.id);
  if (!Number.isInteger(requestedId) || requestedId <= 0) return res.status(400).json({ error: 'Invalid user id.' });
  if (req.user.role !== 'admin' && req.user.id !== requestedId) return res.status(403).json({ error: 'Forbidden.' });

  const user = db.prepare('SELECT id, name, email, role, phone, balance, created_at FROM users WHERE id = ?').get(requestedId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  return res.json(user);
});

app.put('/api/users/:id', authenticateToken, (req, res) => {
  const requestedId = Number(req.params.id);
  if (!Number.isInteger(requestedId) || requestedId <= 0) return res.status(400).json({ error: 'Invalid user id.' });
  if (req.user.role !== 'admin' && req.user.id !== requestedId) return res.status(403).json({ error: 'Forbidden.' });

  const { name, phone } = req.body || {};
  if (!name && !phone) return res.status(400).json({ error: 'Provide at least one editable field: name, phone.' });

  const current = db.prepare('SELECT id FROM users WHERE id = ?').get(requestedId);
  if (!current) return res.status(404).json({ error: 'User not found.' });

  const nextName = typeof name === 'string' ? name.trim() : undefined;
  const nextPhone = typeof phone === 'string' ? phone.trim() : undefined;

  if (nextName) db.prepare('UPDATE users SET name = ? WHERE id = ?').run(nextName, requestedId);
  if (nextPhone) db.prepare('UPDATE users SET phone = ? WHERE id = ?').run(nextPhone, requestedId);

  const updated = db.prepare('SELECT id, name, email, role, phone, balance, created_at FROM users WHERE id = ?').get(requestedId);
  return res.json({ message: 'Updated safely.', user: updated });
});

app.get('/api/admin/users', authenticateToken, requireRole('admin'), (_req, res) => {
  const users = db.prepare('SELECT id, name, email, role, phone, balance, created_at FROM users ORDER BY id').all();
  res.json({ total: users.length, users });
});

app.get('/api/orders/:id', authenticateToken, (req, res) => {
  const orderId = Number(req.params.id);
  if (!Number.isInteger(orderId) || orderId <= 0) return res.status(400).json({ error: 'Invalid order id.' });

  const order = db.prepare('SELECT id, user_id, item, amount, status, address, created_at FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Order not found.' });
  if (req.user.role !== 'admin' && req.user.id !== order.user_id) return res.status(403).json({ error: 'Forbidden.' });

  res.json(order);
});

app.get('/api/products', authenticateToken, (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 64);
  const like = `%${q}%`;
  const products = db.prepare(
    'SELECT id, name, price, stock, created_at FROM products WHERE name LIKE ? ORDER BY id'
  ).all(like);
  res.json({ products, count: products.length });
});

// Safe SSRF handling: allow only explicit trusted host.
app.get('/api/fetch', authenticateToken, requireRole('admin'), async (req, res) => {
  const target = String(req.query.url || '').trim();
  if (!target) return res.status(400).json({ error: 'Provide ?url=' });

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return res.status(400).json({ error: 'Invalid URL.' });
  }

  const allowedHosts = new Set(['jsonplaceholder.typicode.com']);
  const disallowed = isPrivateHost(parsed.hostname) || !['https:'].includes(parsed.protocol);
  if (disallowed || !allowedHosts.has(parsed.hostname)) {
    return res.status(400).json({ error: 'Target URL blocked by SSRF policy.' });
  }

  try {
    const upstream = await fetch(parsed.toString(), { method: 'GET' });
    const text = await upstream.text();
    return res.json({ fetched_from: parsed.toString(), preview: text.slice(0, 200) });
  } catch {
    return res.status(502).json({ error: 'Upstream fetch failed.' });
  }
});

app.use((err, _req, res, _next) => {
  if (err && /CORS/i.test(err.message || '')) {
    return res.status(403).json({ error: 'CORS blocked for this origin.' });
  }
  return res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`SAFE API running at http://localhost:${PORT}`);
  console.log('Login users:');
  console.log(' - alice@example.com / password123 (user)');
  console.log(' - bob@example.com / password123 (user)');
  console.log(' - admin@example.com / password123 (admin)');
});

function authenticateToken(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing bearer token.' });
  const token = auth.slice(7).trim();
  if (!token) return res.status(401).json({ error: 'Missing bearer token.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.user = { id: decoded.id, email: decoded.email, role: decoded.role };
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) return res.status(403).json({ error: 'Forbidden.' });
    return next();
  };
}

function seedIfNeeded() {
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (userCount > 0) return;

  const users = [
    ['Alice Kumar', 'alice@example.com', hash('password123'), 'user', '+91-9876543210', 5000],
    ['Bob Sharma', 'bob@example.com', hash('password123'), 'user', '+91-9123456789', 12000],
    ['Admin User', 'admin@example.com', hash('password123'), 'admin', '+91-9000000000', 999999],
  ];
  const addUser = db.prepare('INSERT INTO users (name, email, password_hash, role, phone, balance) VALUES (?, ?, ?, ?, ?, ?)');
  for (const row of users) addUser.run(...row);

  db.prepare('INSERT INTO orders (user_id, item, amount, status, address) VALUES (?, ?, ?, ?, ?)')
    .run(1, 'iPhone 15 Pro', 134900, 'delivered', '12 MG Road, Pune 411001');
  db.prepare('INSERT INTO orders (user_id, item, amount, status, address) VALUES (?, ?, ?, ?, ?)')
    .run(2, 'MacBook Air M3', 114900, 'processing', '45 Brigade Road, Bangalore 560001');

  db.prepare('INSERT INTO products (name, price, stock) VALUES (?, ?, ?)').run('iPhone 15 Pro', 134900, 50);
  db.prepare('INSERT INTO products (name, price, stock) VALUES (?, ?, ?)').run('MacBook Air M3', 114900, 30);
  db.prepare('INSERT INTO products (name, price, stock) VALUES (?, ?, ?)').run('AirPods Pro', 24900, 200);
}

function hash(value) {
  return bcrypt.hashSync(value, 10);
}

function isPrivateHost(host) {
  const lower = String(host || '').toLowerCase();
  if (['localhost', '127.0.0.1', '::1'].includes(lower)) return true;
  if (/^10\./.test(lower)) return true;
  if (/^192\.168\./.test(lower)) return true;
  if (/^169\.254\./.test(lower)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(lower)) return true;
  return false;
}
