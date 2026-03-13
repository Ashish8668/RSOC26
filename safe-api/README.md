# Safe API Manual Demo Guide (Windows PowerShell)

This API is the hardened counterpart of `vulnerable-api`.

## Goal of this README
- Run the same tests as vulnerable-api.
- Show secure expected behavior (`401/403/429`, minimized data, blocked SSRF).
- Explain why this is the correct behavior.

## Run the API
Open PowerShell:

```powershell
cd C:\Users\ashis\OneDrive\Desktop\RSOC26\safe-api
npm install
copy .env.template .env
node index.js
```

Base URL: `http://localhost:3002`

Demo users:
- `alice@example.com / password123` (user)
- `bob@example.com / password123` (user)
- `admin@example.com / password123` (admin)

---

## Quick test setup (copy-paste once)
Open a second PowerShell window for testing:

```powershell
$base = "http://localhost:3002"

$loginBody = @{
  email = "alice@example.com"
  password = "password123"
} | ConvertTo-Json

$login = Invoke-RestMethod -Method Post -Uri "$base/api/auth/login" -ContentType "application/json" -Body $loginBody
$token = $login.token

"Alice token: $token"
```

---

## 1) BOLA protection
### Command
```powershell
Invoke-RestMethod -Method Get -Uri "$base/api/users/1" -Headers @{ Authorization = "Bearer $token" }
try {
  Invoke-RestMethod -Method Get -Uri "$base/api/users/2" -Headers @{ Authorization = "Bearer $token" }
} catch {
  $_.Exception.Response.StatusCode.value__
}
```

### Expected in safe-api
- Own profile: success (`200` behavior).
- Other user profile: blocked with `403`.

### Why this is correct
- Ownership checks enforce object-level authorization.

---

## 2) Vertical privilege protection (user -> admin)
### Command
```powershell
try {
  Invoke-RestMethod -Method Get -Uri "$base/api/admin/users" -Headers @{ Authorization = "Bearer $token" }
} catch {
  $_.Exception.Response.StatusCode.value__
}
```

### Expected in safe-api
- `403 Forbidden`.

### Why this is correct
- Admin route requires admin role.

---

## 3) Authentication and JWT strictness

### 3.1 Missing token
```powershell
try {
  Invoke-RestMethod -Method Get -Uri "$base/api/users/1"
} catch {
  $_.Exception.Response.StatusCode.value__
}
```
Expected: `401`.

### 3.2 Malformed token
```powershell
try {
  Invoke-RestMethod -Method Get -Uri "$base/api/users/1" -Headers @{ Authorization = "Bearer malformed.token.value" }
} catch {
  $_.Exception.Response.StatusCode.value__
}
```
Expected: `401`.

### 3.3 `alg:none` forged token
```powershell
$algNone = "eyJhbGciOiJub25lIn0.eyJpZCI6MSwicm9sZSI6InVzZXIifQ."
try {
  Invoke-RestMethod -Method Get -Uri "$base/api/users/1" -Headers @{ Authorization = "Bearer $algNone" }
} catch {
  $_.Exception.Response.StatusCode.value__
}
```
Expected: `401`.

### Why this is correct
- Signature verification + allowed algorithm check rejects forged tokens.

---

## 4) Rate limiting on login
### Command
```powershell
1..20 | ForEach-Object {
  $body = @{ email="alice@example.com"; password="wrongpass" } | ConvertTo-Json
  try {
    Invoke-RestMethod -Method Post -Uri "$base/api/auth/login" -ContentType "application/json" -Body $body | Out-Null
    200
  } catch {
    $_.Exception.Response.StatusCode.value__
  }
}
```

### Expected in safe-api
- Early attempts: `401`.
- After threshold: `429 Too Many Requests`.

### Why this is correct
- Brute-force risk reduced with login throttling.

---

## 5) Sensitive data minimization
### Command
```powershell
Invoke-RestMethod -Method Get -Uri "$base/api/users" -Headers @{ Authorization = "Bearer $token" }
```

### Expected in safe-api
- No `password_hash`, no SSN, no card number fields in response.
- Only safe business fields.

### Why this is correct
- Response minimization prevents PII leakage.

---

## 6) SQLi resistance
### Command
```powershell
Invoke-RestMethod -Method Get -Uri "$base/api/products?q=' OR 1=1--" -Headers @{ Authorization = "Bearer $token" }
```

### Expected in safe-api
- Normal response, no SQL error leakage.
- Input treated as value, not SQL syntax.

### Why this is correct
- Parameterized query prevents SQL injection.

---

## 7) SSRF protection
Use admin token first:

```powershell
$adminBody = @{ email="admin@example.com"; password="password123" } | ConvertTo-Json
$adminLogin = Invoke-RestMethod -Method Post -Uri "$base/api/auth/login" -ContentType "application/json" -Body $adminBody
$adminToken = $adminLogin.token
```

Now test blocked internal URL:

```powershell
try {
  Invoke-RestMethod -Method Get -Uri "$base/api/fetch?url=http://169.254.169.254/latest/meta-data/" -Headers @{ Authorization = "Bearer $adminToken" }
} catch {
  $_.Exception.Response.StatusCode.value__
}
```

### Expected in safe-api
- `400` with blocked target message.

### Why this is correct
- Private/link-local/internal targets are denied by SSRF policy.

---

## 8) Quick summary for teacher
- Same business endpoints as vulnerable-api, but secure controls are enforced.
- Correct statuses are visible (`401`, `403`, `429`, `400`).
- Scanner should show significantly fewer/high-lower findings versus vulnerable-api.
