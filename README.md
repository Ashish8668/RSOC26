# 🛡️ APIGuard — Automated API Security Scanner
### RSOC 2026 Hackathon Project

---

## 🗂️ Project Structure

```
RSOC26/
├── scanner/
│   ├── server/          ← Express backend (runs locally on :5000)
│   └── client/          ← React frontend (runs on :3000)
└── vulnerable-api/      ← Demo target with intentional bugs (:3001)
```

---

## ⚡ Quick Start (Step by Step)

### Step 1 — Install Node.js
Download from https://nodejs.org (choose LTS version)
Verify: `node --version`

### Step 2 — Start Vulnerable Demo API
```bash
cd RSOC26/vulnerable-api
npm install
node index.js
```
Runs on http://localhost:3001  ⚠️ Intentionally insecure!

### Step 3 — Start Scanner Backend
```bash
cd RSOC26/scanner/server
npm install
copy .env.template .env
node index.js
```
Runs on http://localhost:5000

### Step 4 — Start React Frontend
```bash
cd RSOC26/scanner/client
npm install
copy .env.template .env
npm start
```
Runs on http://localhost:3000

---

## 🔥 Firebase Setup (Optional)
1. Go to https://console.firebase.google.com
2. Create a new project (free)
3. Enable Firestore Database
4. Client .env: Project Settings → Your Apps → Add Web App → copy config
5. Server .env: Project Settings → Service Accounts → Generate New Private Key

> Without Firebase the scanner works in in-memory mode — fine for demo!
> If server `.env` only has web keys (`FIREBASE_API_KEY`, `FIREBASE_AUTH_DOMAIN`, etc.), scanner still runs in-memory mode.
> For persistent scan history in Firestore from backend, use Admin SDK fields: `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY`.

---

## 🎮 Demo Script for Judges

1. Show: http://localhost:3001/api/admin/users  ← No auth needed!
2. Show: http://localhost:3001/api              ← JWT secret exposed!
3. Scanner: Enter http://localhost:3001, click Start Scan
4. Watch live findings appear one by one
5. Show Report with charts + AI remediation

---

## 🛡️ Vulnerabilities Detected

| Module | OWASP | Severity |
|--------|-------|----------|
| BOLA / IDOR | API1:2023 | Critical |
| Auth Bypass | API2:2023 | Critical |
| JWT Security | API2:2023 | Critical |
| Rate Limiting | API4:2023 | High |
| Data Exposure | API3:2023 | Critical |
| SQL Injection | API8:2023 | Critical |
| CORS Misconfig | API8:2023 | Medium |
| Missing Headers | API8:2023 | Medium |
