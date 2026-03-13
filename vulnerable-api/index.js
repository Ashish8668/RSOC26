// ⚠️  INTENTIONALLY VULNERABLE API — FOR DEMO/TESTING ONLY ⚠️
// Do NOT deploy this in production. Every vulnerability here is deliberate.

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = 3001;

// VULNERABILITY: Wildcard CORS — any origin can access this API
app.use(cors({ origin: '*' }));
app.use(express.json());

// VULNERABILITY: No security headers (no helmet)

// ─── DATABASE SETUP ───────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'vuln_demo.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, email TEXT UNIQUE,
    password TEXT, role TEXT DEFAULT 'user',
    phone TEXT, ssn TEXT, credit_card TEXT, balance REAL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, item TEXT, amount REAL,
    status TEXT DEFAULT 'pending', address TEXT
  );
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, price REAL, stock INTEGER
  );
`);

// Seed data
const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get();
if (userCount.c === 0) {
  db.prepare(`INSERT INTO users (name,email,password,role,phone,ssn,credit_card,balance) VALUES (?,?,?,?,?,?,?,?)`)
    .run('Alice Kumar','alice@example.com','$2b$10$hashedpassword_alice','user','+91-9876543210','SSN-123-45-6789','4111-1111-1111-1111',5000);
  db.prepare(`INSERT INTO users (name,email,password,role,phone,ssn,credit_card,balance) VALUES (?,?,?,?,?,?,?,?)`)
    .run('Bob Sharma','bob@example.com','$2b$10$hashedpassword_bob','user','+91-9123456789','SSN-987-65-4321','5500-0000-0000-0004',12000);
  db.prepare(`INSERT INTO users (name,email,password,role,phone,ssn,credit_card,balance) VALUES (?,?,?,?,?,?,?,?)`)
    .run('Admin User','admin@example.com','$2b$10$hashedpassword_admin','admin','+91-9000000000','SSN-000-00-0000','4000-0000-0000-0002',999999);
  db.prepare(`INSERT INTO orders (user_id,item,amount,status,address) VALUES (?,?,?,?,?)`)
    .run(1,'iPhone 15 Pro',134900,'delivered','12 MG Road, Pune 411001');
  db.prepare(`INSERT INTO orders (user_id,item,amount,status,address) VALUES (?,?,?,?,?)`)
    .run(2,'MacBook Air M3',114900,'processing','45 Brigade Road, Bangalore 560001');
  db.prepare(`INSERT INTO products (name,price,stock) VALUES (?,?,?)`).run('iPhone 15 Pro',134900,50);
  db.prepare(`INSERT INTO products (name,price,stock) VALUES (?,?,?)`).run('MacBook Air M3',114900,30);
  db.prepare(`INSERT INTO products (name,price,stock) VALUES (?,?,?)`).run('AirPods Pro',24900,200);
  console.log('Seed data inserted');
}

// WEAK hardcoded JWT secret
const JWT_SECRET = 'secret123';

// VULN 1: No rate limiting on login + returns password hash
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'User not found' });
  if (password !== 'password123') return res.status(401).json({ error: 'Invalid credentials' });

  // VULN: No expiry, weak secret, sensitive data in payload
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, password: user.password }, JWT_SECRET);

  // VULN: Returns password hash, SSN, credit card!
  res.json({ message: 'Login successful', token, user });
});

// VULN 2: BOLA — no ownership check
app.get('/api/users/:id', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(user); // Returns ALL fields including ssn, credit_card
});

// VULN 3: Admin endpoint with NO authentication
app.get('/api/admin/users', (req, res) => {
  const users = db.prepare('SELECT * FROM users').all();
  res.json({ total: users.length, users });
});

// VULN 4: SQL Injection via string concatenation
app.get('/api/products', (req, res) => {
  const search = req.query.q || '';
  try {
    const query = `SELECT * FROM products WHERE name LIKE '%${search}%'`;
    const products = db.prepare(query).all();
    res.json({ products, query_used: query }); // Also exposes raw SQL!
  } catch (err) {
    res.status(500).json({ error: 'DB Error', details: err.message, query: `SELECT * FROM products WHERE name LIKE '%${search}%'` });
  }
});

// VULN 5: BOLA on orders
app.get('/api/orders/:id', (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});

// VULN 6: Mass assignment — user can set role=admin
app.put('/api/users/:id', (req, res) => {
  const { name, email, role, balance } = req.body;
  db.prepare('UPDATE users SET name=?, email=?, role=?, balance=? WHERE id=?')
    .run(name, email, role, balance, req.params.id);
  res.json({ message: 'Updated', role, balance });
});

// VULN 7: All users with all sensitive fields
app.get('/api/users', (req, res) => {
  res.json(db.prepare('SELECT * FROM users').all());
});

// VULN 8: Exposes JWT secret in response!
app.get('/api', (req, res) => {
  res.json({
    name: 'ShopEasy API', version: '1.0.0',
    jwt_secret: JWT_SECRET,  // Never do this!
    endpoints: ['POST /api/auth/login','GET /api/users/:id','GET /api/admin/users','GET /api/products?q=','GET /api/orders/:id']
  });
});

app.get('/health', (req, res) => res.json({ status: 'ok', server: 'vulnerable-api', port: PORT }));

app.listen(PORT, () => {
  console.log(`\n⚠️  VULNERABLE API on http://localhost:${PORT}`);
  console.log(`   POST /api/auth/login       email: alice@example.com  password: password123`);
  console.log(`   GET  /api/users/1          BOLA — change to /2 to see another user's data`);
  console.log(`   GET  /api/admin/users      No auth needed!`);
  console.log(`   GET  /api/products?q='     SQL injection`);
  console.log(`   GET  /api                  JWT secret exposed!\n`);
});
