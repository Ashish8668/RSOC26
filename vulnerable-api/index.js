// Intentionally vulnerable API for scanner demos only.
// Do not deploy this service in production.

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const http = require('http');
const https = require('https');

const app = express();
const PORT = 3001;
const JWT_SECRET = 'secret123';

app.use(cors({ origin: '*' })); // Vulnerable: wildcard CORS.
app.use(express.json());

const db = new Database(path.join(__dirname, 'vuln_demo.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    phone TEXT,
    ssn TEXT,
    credit_card TEXT,
    balance REAL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    item TEXT,
    amount REAL,
    status TEXT DEFAULT 'pending',
    address TEXT
  );
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    stock INTEGER
  );
`);

seedIfNeeded();

// Vulnerable login:
// 1) No rate-limit, brute-force friendly
// 2) Token has no expiry
// 3) Token contains sensitive password hash
// 4) Returns full user object with PII
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'User not found' });
  if (password !== 'password123') return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, password: user.password },
    JWT_SECRET
  );
  return res.json({ message: 'Login successful', token, user });
});

// Insecure auth middleware:
// - missing token => 401
// - token signature is never verified
// - malformed token falls back to user #1
function insecureAuthRequired(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing bearer token' });
  const token = auth.slice(7).trim();
  if (!token) return res.status(401).json({ error: 'Missing bearer token' });

  const payload = insecureDecode(token);
  if (payload) {
    req.user = {
      id: Number(payload.id) || 1,
      email: payload.email || 'unknown@example.com',
      role: payload.role || 'user',
      raw: payload,
    };
    return next();
  }

  // Vulnerability: malformed tokens still become authenticated user.
  req.user = { id: 1, email: 'alice@example.com', role: 'user', raw: { malformed: true } };
  return next();
}

function insecureDecode(token) {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return payload;
  } catch {
    return null;
  }
}

app.get('/api/profile', insecureAuthRequired, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  return res.json({ profile: user, auth_debug: req.user.raw });
});

// Vulnerable BOLA:
// user1 token can read /users/2, /users/3.
app.get('/api/users/:id', insecureAuthRequired, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  return res.json(user);
});

// Vulnerable admin authorization:
// route requires token, but no role check.
app.get('/api/admin/users', insecureAuthRequired, (req, res) => {
  const users = db.prepare('SELECT * FROM users').all();
  return res.json({ requested_by: req.user, total: users.length, users });
});

// Vulnerable SQLi via query concat.
app.get('/api/products', (req, res) => {
  const search = req.query.q || '';
  try {
    const query = `SELECT * FROM products WHERE name LIKE '%${search}%'`;
    const products = db.prepare(query).all();
    return res.json({ products, query_used: query });
  } catch (err) {
    return res.status(500).json({
      error: 'DB Error',
      details: err.message,
      query: `SELECT * FROM products WHERE name LIKE '%${search}%'`,
    });
  }
});

// Vulnerable BOLA on orders.
app.get('/api/orders/:id', insecureAuthRequired, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  return res.json(order);
});

// Vulnerable mass assignment.
app.put('/api/users/:id', insecureAuthRequired, (req, res) => {
  const { name, email, role, balance } = req.body || {};
  db.prepare('UPDATE users SET name=?, email=?, role=?, balance=? WHERE id=?')
    .run(name, email, role, balance, req.params.id);
  return res.json({ message: 'Updated (unsafe)', role, balance });
});

// Vulnerable sensitive data bulk exposure.
app.get('/api/users', (_req, res) => {
  return res.json(db.prepare('SELECT * FROM users').all());
});

// Vulnerable SSRF helper endpoint for demo.
app.get('/api/fetch', async (req, res) => {
  const target = String(req.query.url || '').trim();
  if (!target) return res.status(400).json({ error: 'Provide ?url=' });

  try {
    const data = await fetchUrl(target);
    return res.json({ fetched_from: target, preview: data.slice(0, 200) });
  } catch (e) {
    // Returns backend error details (also unsafe).
    return res.status(500).json({ error: 'Fetch failed', details: e.message, attempted: target });
  }
});

// Vulnerable info disclosure.
app.get('/api', (_req, res) => {
  return res.json({
    name: 'ShopEasy API',
    version: '1.0.0',
    jwt_secret: JWT_SECRET,
    endpoints: [
      'POST /api/auth/login',
      'GET /api/profile',
      'GET /api/users/:id',
      'GET /api/admin/users',
      'GET /api/products?q=',
      'GET /api/orders/:id',
      'GET /api/fetch?url=',
    ],
  });
});

app.get('/health', (_req, res) => res.json({ status: 'ok', server: 'vulnerable-api', port: PORT }));

app.listen(PORT, () => {
  console.log(`VULNERABLE API running on http://localhost:${PORT}`);
  console.log('Use: alice@example.com / password123');
});

function seedIfNeeded() {
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (userCount > 0) return;

  db.prepare('INSERT INTO users (name,email,password,role,phone,ssn,credit_card,balance) VALUES (?,?,?,?,?,?,?,?)')
    .run('Alice Kumar', 'alice@example.com', '$2b$10$hashedpassword_alice', 'user', '+91-9876543210', '123-45-6789', '4111-1111-1111-1111', 5000);
  db.prepare('INSERT INTO users (name,email,password,role,phone,ssn,credit_card,balance) VALUES (?,?,?,?,?,?,?,?)')
    .run('Bob Sharma', 'bob@example.com', '$2b$10$hashedpassword_bob', 'user', '+91-9123456789', '987-65-4321', '5500-0000-0000-0004', 12000);
  db.prepare('INSERT INTO users (name,email,password,role,phone,ssn,credit_card,balance) VALUES (?,?,?,?,?,?,?,?)')
    .run('Admin User', 'admin@example.com', '$2b$10$hashedpassword_admin', 'admin', '+91-9000000000', '000-00-0000', '4000-0000-0000-0002', 999999);

  db.prepare('INSERT INTO orders (user_id,item,amount,status,address) VALUES (?,?,?,?,?)')
    .run(1, 'iPhone 15 Pro', 134900, 'delivered', '12 MG Road, Pune 411001');
  db.prepare('INSERT INTO orders (user_id,item,amount,status,address) VALUES (?,?,?,?,?)')
    .run(2, 'MacBook Air M3', 114900, 'processing', '45 Brigade Road, Bangalore 560001');

  db.prepare('INSERT INTO products (name,price,stock) VALUES (?,?,?)').run('iPhone 15 Pro', 134900, 50);
  db.prepare('INSERT INTO products (name,price,stock) VALUES (?,?,?)').run('MacBook Air M3', 114900, 30);
  db.prepare('INSERT INTO products (name,price,stock) VALUES (?,?,?)').run('AirPods Pro', 24900, 200);
}

function fetchUrl(target) {
  return new Promise((resolve, reject) => {
    const client = target.startsWith('https://') ? https : http;
    const req = client.get(target, { timeout: 1500 }, (resp) => {
      let data = '';
      resp.on('data', chunk => { data += chunk; });
      resp.on('end', () => resolve(data));
    });
    req.on('timeout', () => req.destroy(new Error('upstream timeout')));
    req.on('error', reject);
  });
}
